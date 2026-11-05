/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.AgentConfirmationFacts;
import io.contexa.contexacommon.security.bridge.ArgumentOrigins;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacore.autonomous.event.support.InvocationArguments;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.annotation.ResourceImportance;
import io.contexa.contexacore.autonomous.context.support.ResourceImportanceResolver;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrations;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.context.registry.ResourceContextRegistry;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.RequestIdentity;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class ZeroTrustEventPublisher {

    /** A2-8: the payload key of a protected method call's argument summary ({@link InvocationArguments}). */
    public static final String INVOCATION_ARGUMENTS = InvocationArguments.KEY;

    /** CQ-1: the payload key of the argument origins a host gives a protected method ({@link ArgumentOrigins}). */
    public static final String ARGUMENT_ORIGINS = ArgumentOrigins.KEY;

    private final ApplicationEventPublisher eventPublisher;
    private final TieredStrategyProperties properties;
    private final SecurityContextDataStore securityContextDataStore;
    private final SecurityPlaneProperties securityPlaneProperties;

    @Autowired(required = false)
    private ZeroTrustActionRepository actionRedisRepository;

    @Autowired(required = false)
    private SecurityZeroTrustProperties securityZeroTrustProperties;

    @Autowired(required = false)
    private ResourceContextRegistry resourceContextRegistry;

    /** A1-6: the agent registry, for the sponsor of an agent request; absent when no registry is configured. */
    @Autowired(required = false)
    private AgentRegistry agentRegistry;

    /** A2-11: the token claim names the bridge reads; the defaults when the bridge is not configured. */
    @Autowired(required = false)
    private BridgeProperties bridgeProperties;

    public ZeroTrustEventPublisher(
            ApplicationEventPublisher eventPublisher,
            TieredStrategyProperties properties) {
        this(eventPublisher, properties, null, new SecurityPlaneProperties());
    }

    public ZeroTrustEventPublisher(
            ApplicationEventPublisher eventPublisher,
            TieredStrategyProperties properties,
            SecurityContextDataStore securityContextDataStore,
            SecurityPlaneProperties securityPlaneProperties) {
        this.eventPublisher = eventPublisher;
        this.properties = properties;
        this.securityContextDataStore = securityContextDataStore;
        this.securityPlaneProperties = securityPlaneProperties != null
                ? securityPlaneProperties
                : new SecurityPlaneProperties();
    }

    public void publishAuthenticationSuccess(
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            Map<String, Object> payload) {

        publish(
                ZeroTrustEventCategory.AUTHENTICATION,
                ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS,
                userId,
                sessionId,
                clientIp,
                userAgent,
                null,
                payload
        );

    }

    /** The method has not run: the event describes the authorization check before execution. */
    public static final String METHOD_NOT_RUN = "NOT_RUN";
    /** The method ran and returned. */
    public static final String METHOD_COMPLETED = "COMPLETED";
    /** The method ran and threw: a business failure, not an authorization result. */
    public static final String METHOD_FAILED = "FAILED";
    /** What is known of a check that did not finish. */
    private static final String EFFECT_UNKNOWN = "UNKNOWN";

    public void publishMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        publishMethodAuthorization(methodInvocation, authentication, granted, denialReason, null, null);
    }

    /**
     * @param granted          whether the authorization check let the method run
     * @param executionOutcome {@link #METHOD_COMPLETED} or {@link #METHOD_FAILED} after the method ran, null if unknown
     * @param executionFailure the failure's type when the method threw
     */
    public void publishMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason,
            String executionOutcome,
            String executionFailure) {
        ZeroTrustSpringEvent event = buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                granted,
                denialReason,
                executionOutcome,
                executionFailure
        );
        eventPublisher.publishEvent(event);
    }

    /**
     * The event of a call whose authorization check did not finish (PR-55, PR-84). A store that did not answer, or a check
     * that failed, says nothing about the user: it was recorded as a DENY, and a DENY requires a BLOCK whatever the model
     * answers, so an outage ended in a permanent BLOCK of normal users. What the check would have said is not known.
     *
     * @param checkFailure     the type of the failure that ended the check
     * @param executionOutcome {@link #METHOD_COMPLETED} or {@link #METHOD_FAILED} after the method ran, null if it did not
     * @param executionFailure the failure's type when the method threw
     */
    public void publishUncheckedMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            String checkFailure,
            String executionOutcome,
            String executionFailure) {
        eventPublisher.publishEvent(buildMethodAuthorizationEvent(methodInvocation, authentication, null, null,
                executionOutcome, executionFailure, checkFailure));
    }

    /** The event of an authorization check made before the method runs (a synchronous decision). */
    public ZeroTrustSpringEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        return buildMethodAuthorizationEvent(methodInvocation, authentication, granted, denialReason, METHOD_NOT_RUN, null);
    }

    /**
     * docs/agent B4: the event of an authorization check an enforcement point outside this application describes
     * (an AuthZEN evaluation). Nothing is read from the current request or security context, which belong to the
     * enforcement point's own call; the subject's facts come from the description alone, enriched as every event is
     * (subject kind and lineage, the agent's accountable party).
     */
    public ZeroTrustSpringEvent buildDescribedAuthorizationEvent(String userId, String sessionId, String clientIp,
                                                                 String userAgent, String resource,
                                                                 Map<String, Object> payload, Instant eventTimestamp) {
        return build(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD, userId,
                sessionId, clientIp, userAgent, resource, payload != null ? new HashMap<>(payload) : null,
                eventTimestamp);
    }

    /**
     * The event of a URL authorization policy check of the current request, before any handler runs. It carries the
     * same request and subject facts as a method event, without method facts.
     */
    public ZeroTrustSpringEvent buildRequestAuthorizationEvent(
            Authentication authentication,
            boolean granted,
            String denialReason) {
        return buildMethodAuthorizationEvent(null, authentication, granted, denialReason, METHOD_NOT_RUN, null);
    }

    public ZeroTrustSpringEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason,
            String executionOutcome,
            String executionFailure) {
        return buildMethodAuthorizationEvent(methodInvocation, authentication, Boolean.valueOf(granted), denialReason,
                executionOutcome, executionFailure, null);
    }

    /** {@code granted} is null, and {@code checkFailure} set, when the check did not finish. */
    private ZeroTrustSpringEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            Boolean granted,
            String denialReason,
            String executionOutcome,
            String executionFailure,
            String checkFailure) {

        RequestInfo requestInfo = extractRequestInfoFromContext();
        String effectiveUserId = resolveEffectiveUserId(authentication);
        String methodResource = methodInvocation != null
                ? methodInvocation.getMethod().getDeclaringClass().getSimpleName() + "." + methodInvocation.getMethod().getName()
                : "URL_POLICY";
        String resource = (requestInfo != null && requestInfo.getRequestUri() != null)
                ? requestInfo.getRequestUri()
                : methodResource;

        Map<String, Object> payload = new HashMap<>();
        payload.put("granted", granted != null ? granted : EFFECT_UNKNOWN);
        payload.put("denialReason", denialReason != null ? denialReason : "");
        if (executionOutcome != null) {
            payload.put("methodExecutionOutcome", executionOutcome);
        }
        if (executionFailure != null) {
            payload.put("methodExecutionFailure", executionFailure);
        }
        payload.put("authorizationCheck", methodInvocation != null ? "METHOD_POLICY" : "URL_POLICY");
        if (methodInvocation != null) {
            payload.put("methodName", methodInvocation.getMethod().getName());
            payload.put("className", methodInvocation.getMethod().getDeclaringClass().getName());
        }

        Protectable protectable = methodInvocation != null ? resolveProtectable(methodInvocation) : null;
        if (protectable != null) {
            payload.put("protectableDeclared", true);
            // A2-8: what the caller asked the protected method to do; the decision reads it as untrusted text.
            String invocationArguments = InvocationArguments.summarize(methodInvocation.getMethod(),
                    methodInvocation.getArguments());
            if (invocationArguments != null) {
                payload.put(INVOCATION_ARGUMENTS, invocationArguments);
            }
            // CQ-1: where the argument values came from, as the host states it; its own key, only when the host gave
            // some, written as the settings let the decision prompt state them.
            putArgumentOrigins(methodInvocation.getArguments(), payload);
            payload.put("protectableSync", protectable.sync());
            payload.put("protectableVerificationRequired", protectable.verificationRequired());
            payload.put("protectableMethod", methodInvocation.getMethod().getDeclaringClass().getName()
                    + "." + methodInvocation.getMethod().getName());
            String protectableResourceId = methodInvocation.getMethod().getDeclaringClass().getName()
                    + "#" + methodInvocation.getMethod().getName();
            payload.put("protectableResourceId", protectableResourceId);
            payload.put("resourceId", protectableResourceId);
            String resourceUrlTemplate = currentResourceUrlTemplate();
            if (StringUtils.hasText(resourceUrlTemplate)) {
                payload.put("protectableResourceUrl", resourceUrlTemplate);
                payload.put("resourceUrlTemplate", resourceUrlTemplate);
            }
            if (requestInfo != null && StringUtils.hasText(requestInfo.getMethod())) {
                payload.put("protectableHttpMethod", requestInfo.getMethod());
            }
        }

        if (requestInfo != null) {
            payload.put("httpUri", requestInfo.getRequestUri());
            payload.put("requestPath", requestInfo.getRequestUri());
            payload.put("requestUri", requestInfo.getRequestUri());
            payload.put("httpMethod", requestInfo.getMethod());
            payload.put("eventId", requestInfo.getRequestId());
            payload.put("requestId", requestInfo.getRequestId());
            payload.put("correlationId", requestInfo.getRequestId());
            if (requestInfo.getClientRequestId() != null) {
                // The caller's own request id, kept for log correlation only; never an identifier of the processing.
                payload.put("clientRequestId", requestInfo.getClientRequestId());
            }
            payload.put("contextBindingHash", requestInfo.getContextBindingHash());
            payload.put("clientIp", requestInfo.getClientIp());
            payload.put("userAgent", requestInfo.getUserAgent());
            if (requestInfo.getUntrustedAnomalySignalClaim() != null) {
                payload.put("untrustedAnomalySignalClaim", requestInfo.getUntrustedAnomalySignalClaim());
            }
            if (requestInfo.getDecisionBoundaryMode() != null) {
                payload.put("decisionBoundaryMode", requestInfo.getDecisionBoundaryMode());
            }
            if (requestInfo.getRequestedModelId() != null) {
                payload.put("requestedModelId", requestInfo.getRequestedModelId());
                payload.put("preferredModel", requestInfo.getRequestedModelId());
            }
            if (requestInfo.getRuntimeTemperature() != null) {
                payload.put("temperature", requestInfo.getRuntimeTemperature());
            }
            if (requestInfo.getRuntimeTopP() != null) {
                payload.put("topP", requestInfo.getRuntimeTopP());
            }
            if (requestInfo.getRuntimeSeed() != null) {
                payload.put("seed", requestInfo.getRuntimeSeed());
            }
            if (requestInfo.getRuntimeMaxTokens() != null) {
                payload.put("maxTokens", requestInfo.getRuntimeMaxTokens());
            }
            if (requestInfo.getRuntimeDisableRetries() != null) {
                payload.put("disableRetries", requestInfo.getRuntimeDisableRetries());
            }
            if (requestInfo.getRuntimeDisableOllamaThinking() != null) {
                payload.put("disableOllamaThinking", requestInfo.getRuntimeDisableOllamaThinking());
            }
            if (requestInfo.getSimulatedUserAgentLabel() != null) {
                payload.put("simulatedUserAgentLabel", requestInfo.getSimulatedUserAgentLabel());
            }
            payload.put("isNewSession", requestInfo.getIsNewSession());
            if (requestInfo.getSessionCreatedAt() != null) {
                payload.put("sessionCreatedAt", requestInfo.getSessionCreatedAt().toString());
            }
            payload.put("isNewUser", requestInfo.getIsNewUser());
            payload.put("isNewDevice", requestInfo.getIsNewDevice());
            payload.put("recentRequestCount", requestInfo.getRecentRequestCount());
            payload.put("failedLoginAttempts", requestInfo.getFailedLoginAttempts());
            payload.put("baselineConfidence", requestInfo.getBaselineConfidence());
            payload.put("isSensitiveResource", requestInfo.getIsSensitiveResource());
            if (requestInfo.getAuthMethod() != null) {
                payload.put("authMethod", requestInfo.getAuthMethod());
            }
            if (requestInfo.getResourceSensitivity() != null) {
                payload.put("resourceSensitivity", requestInfo.getResourceSensitivity());
            }
            if (requestInfo.getResourceBusinessLabel() != null) {
                payload.put("resourceLabel", requestInfo.getResourceBusinessLabel());
            }
            if (requestInfo.getResourceAuthorText() != null) {
                payload.put("resourceAuthorText", requestInfo.getResourceAuthorText());
            }
            if (requestInfo.getResourceScope() != null) {
                payload.put("resourceScope", requestInfo.getResourceScope());
            }
            if (requestInfo.getClaimedRecord() != null) {
                payload.put("claimedRecord", requestInfo.getClaimedRecord());
            }
            if (requestInfo.getRequestItems() != null) {
                payload.put("requestItems", requestInfo.getRequestItems());
            }
            if (requestInfo.getResourceId() != null) {
                payload.put("resourceId", requestInfo.getResourceId());
            }
            if (requestInfo.getTenantId() != null) {
                payload.put("tenantId", requestInfo.getTenantId());
            }
            if (requestInfo.getOrganizationId() != null) {
                payload.put("organizationId", requestInfo.getOrganizationId());
            }
            payload.put("mfaVerified", requestInfo.getMfaVerified());
            if (requestInfo.getPreviousPath() != null) {
                payload.put("previousPath", requestInfo.getPreviousPath());
            }
            if (requestInfo.getLastRequestIntervalMs() != null) {
                payload.put("lastRequestIntervalMs", requestInfo.getLastRequestIntervalMs());
            }
            payload.put("userRoles", requestInfo.getUserRoles());
            if (requestInfo.getServletPath() != null) {
                payload.put("servletPath", requestInfo.getServletPath());
            }
            if (requestInfo.getQueryString() != null) {
                payload.put("queryString", requestInfo.getQueryString());
            }
            populateBridgePayload(requestInfo, payload);
            populateRequestContextHints(requestInfo, payload);
            populateTestRunMarker(payload);

            if (requestInfo.getGeoCountry() != null) {
                payload.put("geoCountry", requestInfo.getGeoCountry());
            }
            if (requestInfo.getGeoCity() != null) {
                payload.put("geoCity", requestInfo.getGeoCity());
            }
            if (requestInfo.getGeoLatitude() != null) {
                payload.put("geoLatitude", requestInfo.getGeoLatitude());
            }
            if (requestInfo.getGeoLongitude() != null) {
                payload.put("geoLongitude", requestInfo.getGeoLongitude());
            }
            if (Boolean.TRUE.equals(requestInfo.getImpossibleTravel())) {
                payload.put("impossibleTravel", true);
            }
            // The move facts travel whether or not the host also calls the move impossible (W2-13).
            putIfAbsent(payload, "travelDistanceKm", requestInfo.getTravelDistanceKm());
            putIfAbsent(payload, "travelElapsedMinutes", requestInfo.getTravelElapsedMinutes());
            putIfAbsent(payload, "previousLocation", requestInfo.getPreviousLocation());
            promoteOfficialContextFields(requestInfo, payload);
        }
        promoteProtectableDescriptor(payload);

        populateAuthenticationFallback(authentication, payload);
        populateStoredSecurityContext(effectiveUserId, requestInfo, payload);
        if (granted != null) {
            reconcileAuthorizationDecision(granted, payload);
        } else {
            recordUnfinishedCheck(checkFailure, payload);
        }
        putIfAbsent(payload, "decisionBoundaryMode", securityZeroTrustMode());

        if (actionRedisRepository != null && authentication != null) {
            // docs/agent A5-1: the decision in force for the request's subject, classified as the event records it.
            ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(effectiveUserId,
                    CanonicalExecutionEventMetadataSupport.enrich(consoleFact(payload)));
            ZeroTrustAction currentAction = subject != null ? subject.currentAction(actionRedisRepository)
                    : actionRedisRepository.getCurrentAction(effectiveUserId);
            if (currentAction != null) {
                payload.put("action", currentAction.name());
            }
        }

        return build(
                ZeroTrustEventCategory.AUTHORIZATION,
                ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD,
                effectiveUserId,
                requestInfo != null ? requestInfo.getSessionId() : null,
                requestInfo != null ? requestInfo.getClientIp() : null,
                requestInfo != null ? requestInfo.getUserAgent() : null,
                resource,
                payload,
                requestInfo != null ? requestInfo.getObservedAt() : null
        );
    }

    /**
     * CQ-1: the argument origins a protected method's call carries, as plain maps under {@link #ARGUMENT_ORIGINS}. The
     * excerpt setting and its length are applied here, so the sealed context holds exactly what the prompt may state.
     * A call without origins (none given, or none with a value) adds no key.
     */
    private void putArgumentOrigins(Object[] arguments, Map<String, Object> payload) {
        List<Map<String, Object>> stated = originsPayload(ArgumentOrigins.in(arguments));
        if (!stated.isEmpty()) {
            payload.put(ARGUMENT_ORIGINS, stated);
        }
    }

    /**
     * CQ-1 for a caller that states the origins as plain maps (the {@code argument_origins} of an access evaluation of a
     * tool call, in the shape {@link ArgumentOrigins#toPayload} writes): the payload value a protected method's call
     * would have carried, bounded by the same settings. Empty when no origin has a value.
     */
    public List<Map<String, Object>> statedArgumentOrigins(Object plainOrigins) {
        return originsPayload(ArgumentOrigins.fromPayload(plainOrigins));
    }

    private List<Map<String, Object>> originsPayload(ArgumentOrigins origins) {
        if (origins == null) {
            return List.of();
        }
        TieredStrategyProperties.ArgumentOrigin settings = properties != null ? properties.getArgumentOrigin() : null;
        boolean quote = settings == null || settings.isQuoteExcerpt();
        int maxExcerpt = settings != null ? settings.getMaxExcerptChars() : ArgumentOrigins.MAX_EXCERPT_CHARS;
        return origins.toPayload(quote, maxExcerpt);
    }

    private String currentResourceUrlTemplate() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)
                || attributes.getRequest() == null) {
            return null;
        }
        Object pattern = attributes.getRequest().getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        return pattern == null || !StringUtils.hasText(String.valueOf(pattern))
                ? null
                : String.valueOf(pattern).trim();
    }

    private String securityZeroTrustMode() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getMode() == null) {
            return null;
        }
        return securityZeroTrustProperties.getMode().name();
    }

    public void publish(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            Map<String, Object> payload) {

        publish(category, eventType, userId, null, null, null, null, payload);
    }

    public void publish(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            String resource,
            Map<String, Object> payload) {
        ZeroTrustSpringEvent event = build(
                category,
                eventType,
                userId,
                sessionId,
                clientIp,
                userAgent,
                resource,
                payload,
                null
        );
        eventPublisher.publishEvent(event);
    }

    private ZeroTrustSpringEvent build(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            String resource,
            Map<String, Object> payload,
            Instant eventTimestamp) {

        Map<String, Object> effectivePayload = CanonicalExecutionEventMetadataSupport.enrich(consoleFact(payload));
        putAgentAccountability(effectivePayload);

        return ZeroTrustSpringEvent.builder(this)
                .category(category)
                .eventType(eventType)
                .userId(userId)
                .sessionId(sessionId)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .resource(resource)
                .eventTimestamp(eventTimestamp != null ? eventTimestamp : Instant.now())
                .payload(effectivePayload)
                .build();
    }

    private String resolveEffectiveUserId(Authentication authentication) {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                String requestedUserId = RequestIdentity.userId(attrs.getRequest());
                if (StringUtils.hasText(requestedUserId)) {
                    return requestedUserId;
                }
            }
        } catch (Exception e) {
            log.error("Failed to resolve effective user id from request context", e);
        }
        return authentication != null ? authentication.getName() : null;
    }
    private TieredStrategyProperties.Security getSecurity() {
        return properties != null ? properties.getSecurity() : null;
    }

    private RequestInfo extractRequestInfoFromContext() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                return RequestInfoExtractor.extract(request, getSecurity());
            }
        } catch (Exception e) {
            log.error("Failed to extract request info from context", e);
        }
        return null;
    }

    private void populateBridgePayload(RequestInfo requestInfo, Map<String, Object> payload) {
        BridgeResolutionResult bridgeResolutionResult = requestInfo.getBridgeResolutionResult();
        if (bridgeResolutionResult == null) {
            return;
        }

        payload.put("bridgeCoverageLevel", bridgeResolutionResult.coverageReport().level().name());
        payload.put("bridgeCoverageScore", bridgeResolutionResult.coverageReport().score());
        putIfPresent(payload, "bridgeCoverageSummary", bridgeResolutionResult.coverageReport().summary());
        payload.put("bridgeMissingContexts", bridgeResolutionResult.coverageReport().missingContexts().stream()
                .map(MissingBridgeContext::name)
                .collect(Collectors.toList()));
        if (!bridgeResolutionResult.coverageReport().remediationHints().isEmpty()) {
            payload.put("bridgeRemediationHints", bridgeResolutionResult.coverageReport().remediationHints());
        }
        AuthenticationStamp authenticationStamp = bridgeResolutionResult.authenticationStamp();
        if (authenticationStamp != null) {
            putIfAbsent(payload, "bridgeAuthenticationSource", authenticationStamp.authenticationSource());
            // A class name the bridge used in place of an unstated fact is kept apart from the login facts.
            if (isClassNameFallback(authenticationStamp, "principalTypeEvidenceState")) {
                putIfAbsent(payload, "principalClass", authenticationStamp.principalType());
            } else {
                putIfAbsent(payload, "principalType", authenticationStamp.principalType());
            }
            if (isClassNameFallback(authenticationStamp, "authenticationTypeEvidenceState")) {
                putIfAbsent(payload, "authenticationClass", authenticationStamp.authenticationType());
            } else {
                putIfAbsent(payload, "authenticationType", authenticationStamp.authenticationType());
            }
            putIfAbsent(payload, "authenticationAssurance", authenticationStamp.authenticationAssurance());
            putIfAbsent(payload, "mfaVerified", authenticationStamp.mfaCompleted());
            if (authenticationStamp.authenticationTime() != null) {
                putIfAbsent(payload, "authenticationTime", authenticationStamp.authenticationTime().toString());
            }
            Object accountCreatedAt = authenticationStamp.attributes().get("accountCreatedAt");
            if (accountCreatedAt != null) {
                putIfAbsent(payload, "accountCreatedAt", accountCreatedAt.toString());
            }
            Object challengeVerifiedAt = authenticationStamp.attributes().get("challengeVerifiedAt");
            if (challengeVerifiedAt != null) {
                putIfAbsent(payload, "challengeVerifiedAt", challengeVerifiedAt.toString());
            }
            // The session's last MFA: a passed challenge, else a multi-factor login.
            if (challengeVerifiedAt != null) {
                putIfAbsent(payload, "lastMfaUsedAt", challengeVerifiedAt.toString());
            } else if (Boolean.TRUE.equals(authenticationStamp.mfaCompleted())
                    && authenticationStamp.authenticationTime() != null) {
                putIfAbsent(payload, "lastMfaUsedAt", authenticationStamp.authenticationTime().toString());
            }
            if (!authenticationStamp.authorities().isEmpty()) {
                payload.put("authorities", mergeDistinctStringLists(
                        payload.get("authorities"),
                        sanitizeEvidenceAuthorities(authenticationStamp.authorities())));
            }
            Object tenantId = authenticationStamp.attributes().get("tenantId");
            Object organizationId = firstNonNull(
                    authenticationStamp.attributes().get("organizationId"),
                    authenticationStamp.attributes().get("orgId"));
            putIfAbsent(payload, "tenantId", tenantId);
            putIfAbsent(payload, "organizationId", organizationId);
            putIfAbsent(payload, "orgId", authenticationStamp.attributes().get("orgId"));
            putIfAbsent(payload, "department", authenticationStamp.attributes().get("department"));
            putEvidenceStates(payload, authenticationStamp.attributes());
            // The principal an explicit handoff named differs from the one the request resolved to.
            if (Boolean.TRUE.equals(authenticationStamp.attributes().get("bridgeHandoffConflict"))) {
                payload.putIfAbsent("bridgeHandoffConflict", true);
                putIfAbsent(payload, "bridgeHandoffPrincipalId", authenticationStamp.attributes().get("bridgeHandoffPrincipalId"));
                putIfAbsent(payload, "bridgeResolvedPrincipalId", authenticationStamp.principalId());
            }
        }

        AuthorizationStamp authorizationStamp = bridgeResolutionResult.authorizationStamp();
        if (authorizationStamp != null) {
            putIfAbsent(payload, "bridgeAuthorizationSource", authorizationStamp.decisionSource());
            putIfAbsent(payload, "authorizationEffect", authorizationStamp.effect().name());
            putIfAbsent(payload, "privileged", authorizationStamp.privileged());
            putIfAbsent(payload, "policyId", authorizationStamp.policyId());
            putIfAbsent(payload, "policyVersion", authorizationStamp.policyVersion());
            if (authorizationStamp.decisionTime() != null) {
                putIfAbsent(payload, "authorizationDecisionTime", authorizationStamp.decisionTime().toString());
            }
            putEvidenceStates(payload, authorizationStamp.attributes());
            // Authority names that only suggest privilege; the bridge marks them a heuristic hint.
            Object privilegedSignals = authorizationStamp.attributes().get("privilegedAuthoritySignals");
            if (privilegedSignals instanceof List<?> signals && !signals.isEmpty()) {
                payload.putIfAbsent("privilegedAuthoritySignals", List.copyOf(signals));
                putIfAbsent(payload, "privilegedAuthoritySignalPurpose",
                        authorizationStamp.attributes().get("privilegedAuthoritySignalPurpose"));
            }
            // Authorization evidence that disagreed, and how the bridge settled it.
            if (Boolean.TRUE.equals(authorizationStamp.attributes().get("authorizationConflict"))) {
                payload.putIfAbsent("authorizationConflict", true);
                putIfAbsent(payload, "authorizationConflictSelected", authorizationStamp.effect().name());
                putIfAbsent(payload, "authorizationConflictResolution",
                        authorizationStamp.attributes().get("authorizationConflictResolution"));
                putIfAbsent(payload, "authorizationConflictEvidence",
                        authorizationStamp.attributes().get("authorizationConflictEvidence"));
            }
            if (!authorizationStamp.scopeTags().isEmpty()) {
                payload.putIfAbsent("scopeTags", authorizationStamp.scopeTags());
            }
            List<String> effectiveRoles = sanitizeRoleTokens(authorizationStamp.effectiveRoles());
            if (!effectiveRoles.isEmpty()) {
                payload.putIfAbsent("effectiveRoles", effectiveRoles);
            }
            List<String> effectivePermissions = sanitizePermissionTokens(authorizationStamp.effectiveAuthorities());
            if (!effectivePermissions.isEmpty()) {
                payload.putIfAbsent("effectivePermissions", effectivePermissions);
            }
            List<String> authorityEvidence = sanitizeAuthorityTokens(authorizationStamp.effectiveAuthorities());
            if (!authorityEvidence.isEmpty()) {
                payload.put("authorities", mergeDistinctStringLists(payload.get("authorities"), authorityEvidence));
            }
        }

        DelegationStamp delegationStamp = bridgeResolutionResult.delegationStamp();
        if (delegationStamp != null) {
            putIfAbsent(payload, "bridgeDelegationSource", delegationStamp.attributes().get("delegationResolver"));
            putIfAbsent(payload, "delegated", delegationStamp.delegated());
            putIfAbsent(payload, "agentId", delegationStamp.agentId());
            // A1-6: the person who delegated the work; a stamp that states no delegation names no delegator.
            if (delegationStamp.delegated()) {
                putIfAbsent(payload, "delegatorId", delegationStamp.subjectId());
            }
            putIfAbsent(payload, "objectiveId", delegationStamp.objectiveId());
            putIfAbsent(payload, "objectiveFamily", delegationStamp.objectiveFamily());
            putIfAbsent(payload, "objectiveSummary", delegationStamp.objectiveSummary());
            // A delegation's human approval is its own fact, apart from the business approval of the request (W2-9).
            putIfAbsent(payload, "delegationApprovalRequired", delegationStamp.approvalRequired());
            putIfAbsent(payload, "privilegedExportAllowed", delegationStamp.privilegedExportAllowed());
            putIfAbsent(payload, "containmentOnly", delegationStamp.containmentOnly());
            if (delegationStamp.expiresAt() != null) {
                putIfAbsent(payload, "delegationExpiresAt", delegationStamp.expiresAt().toString());
            }
            if (!delegationStamp.allowedOperations().isEmpty()) {
                payload.putIfAbsent("allowedOperations", delegationStamp.allowedOperations());
            }
            if (!delegationStamp.allowedResources().isEmpty()) {
                payload.putIfAbsent("allowedResources", delegationStamp.allowedResources());
            }
            // A1-1: how an access token stated the delegation; prior actors are information only (RFC 8693).
            Map<String, Object> delegationAttributes = delegationStamp.attributes();
            putIfAbsent(payload, "delegationTokenForm", delegationAttributes.get("delegationTokenForm"));
            putIfAbsent(payload, "delegationEvidenceState", delegationAttributes.get("delegationEvidenceState"));
            putIfAbsent(payload, "delegationChainDepth", delegationAttributes.get("delegationChainDepth"));
            if (delegationAttributes.get("delegationPriorActors") instanceof List<?> priorActors && !priorActors.isEmpty()) {
                payload.putIfAbsent("delegationPriorActors", priorActors);
            }
            putIfAbsent(payload, "delegationSubjectType", delegationAttributes.get("delegationSubjectType"));
            putIfAbsent(payload, "delegationExpiresAtSource", delegationAttributes.get("delegationExpiresAtSource"));
            putIfAbsent(payload, "delegationTokenClientId", delegationAttributes.get("tokenClientId"));
            // A1-8: whether the person the agent acts for may make the request, as the policies found it.
            putIfAbsent(payload, "delegatorAuthority", currentRequestAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY));
        }
    }

    private static Object currentRequestAttribute(String name) {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest().getAttribute(name)
                : null;
    }

    /** How each bridged fact was established (explicit, derived fallback, class name fallback, unavailable). */
    private void putEvidenceStates(Map<String, Object> payload, Map<String, Object> attributes) {
        attributes.forEach((key, value) -> {
            if (key.endsWith("EvidenceState") && value != null && !value.toString().isBlank()) {
                payload.putIfAbsent(key, value.toString());
            }
        });
    }

    private void populateRequestContextHints(RequestInfo requestInfo, Map<String, Object> payload) {
        if (requestInfo == null || payload == null) {
            return;
        }
        putIfAbsent(payload, "currentResourceFamily", requestInfo.getCurrentResourceFamily());
        putIfAbsent(payload, "currentActionFamily", requestInfo.getCurrentActionFamily());
        putListIfAbsent(payload, "expectedResourceFamilies", requestInfo.getExpectedResourceFamilies());
        putListIfAbsent(payload, "expectedActionFamilies", requestInfo.getExpectedActionFamilies());
        putListIfAbsent(payload, "recentPermissionChanges", requestInfo.getRecentPermissionChanges());
        putIfAbsent(payload, "approvalRequired", requestInfo.getApprovalRequired());
        putIfAbsent(payload, "approvalGranted", requestInfo.getApprovalGranted());
        putIfAbsent(payload, "approvalMissing", requestInfo.getApprovalMissing());
        putIfAbsent(payload, "approvalStatus", requestInfo.getApprovalStatus());
        putIfAbsent(payload, "delegated", requestInfo.getDelegated());
        putIfAbsent(payload, "objectiveDrift", requestInfo.getObjectiveDrift());
        putIfAbsent(payload, "objectiveDriftSummary", requestInfo.getObjectiveDriftSummary());
    }

    void setResourceContextRegistry(ResourceContextRegistry resourceContextRegistry) {
        this.resourceContextRegistry = resourceContextRegistry;
    }

    /**
     * What the host declared about the protected method (W2-11): category, sensitivity, label, type, its one action,
     * privileged and export-sensitive. The category, the action and the privileged flag go under keys of their own,
     * apart from what the request states; a value the request already states stays. A privileged method is a fact of
     * the resource, not an authorization the requester holds, so it never takes the requester's privileged key.
     */
    private void promoteProtectableDescriptor(Map<String, Object> payload) {
        if (resourceContextRegistry == null || !(payload.get("protectableResourceId") instanceof String resourceId)) {
            return;
        }
        resourceContextRegistry.findByResourceId(resourceId).ifPresent(descriptor -> {
            putIfAbsent(payload, "protectableResourceCategory", descriptor.resourceCategory());
            putIfAbsent(payload, "resourceSensitivity", descriptor.sensitivity());
            if (descriptor.importance() != ResourceImportance.UNSPECIFIED) {
                // RL-14: what the host declared on the method, as a fact of its own. A sensitive method also fills
                // the sensitivity when neither the request nor the method states one, so that every reader of the
                // sensitivity sees the same resource.
                putIfAbsent(payload, ResourceImportanceResolver.PAYLOAD_KEY, descriptor.importance().name());
                if (descriptor.importance() == ResourceImportance.SENSITIVE
                        && !hasNonNullPayload(payload, "resourceSensitivity")) {
                    payload.put("resourceSensitivity", ResourceImportance.SENSITIVE.name());
                }
            }
            putIfAbsent(payload, "resourceLabel", descriptor.businessLabel());
            putIfAbsent(payload, "resourceType", descriptor.resourceType());
            if (descriptor.allowedActionFamilies().size() == 1) {
                putIfAbsent(payload, "protectableActionFamily", descriptor.allowedActionFamilies().get(0));
            }
            putIfAbsent(payload, "protectablePrivileged", descriptor.privileged());
            putIfAbsent(payload, "exportSensitive", descriptor.exportSensitive());
        });
    }

    private void promoteOfficialContextFields(RequestInfo requestInfo, Map<String, Object> payload) {
        if (requestInfo == null || requestInfo.getOfficialContextFields() == null || requestInfo.getOfficialContextFields().isEmpty()) {
            return;
        }
        requestInfo.getOfficialContextFields().forEach((key, value) -> putIfAbsent(payload, key, value));
    }

    private void populateAuthenticationFallback(Authentication authentication, Map<String, Object> payload) {
        // A2-11 (AG-12f): what the access token says about how the request was authorised; a session has none.
        CredentialFacts.of(authentication, bridgeProperties != null && bridgeProperties.getDelegation() != null
                        ? bridgeProperties.getDelegation().getToken() : null)
                .ifPresent(facts -> facts.payload().forEach(payload::putIfAbsent));
        String bridgeAuthenticationType = bridgeAuthenticationType(payload);
        if (bridgeAuthenticationType != null && !hasNonNullPayload(payload, "authMethod")) {
            payload.put("authMethod", bridgeAuthenticationType);
        }
        if (authentication == null) {
            return;
        }
        List<String> authorities = sanitizeEvidenceAuthorities(authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority != null ? grantedAuthority.getAuthority() : null)
                .filter(authority -> authority != null && !authority.isBlank())
                .toList());
        if (authorities.isEmpty()) {
            return;
        }

        if (!hasNonNullPayload(payload, "authMethod")) {
            // An MFA authority states the method; without one the method is unknown, not a password login.
            boolean hasMfaAuthority = authorities.stream()
                    .anyMatch(authority -> authority.toUpperCase(Locale.ROOT).contains("MFA"));
            if (hasMfaAuthority) {
                payload.put("authMethod", "mfa");
            }
        }

        if (!hasNonNullPayload(payload, "mfaVerified")) {
            boolean hasMfaAuthority = authorities.stream()
                    .anyMatch(authority -> authority.toUpperCase(Locale.ROOT).contains("MFA"));
            if (hasMfaAuthority) {
                payload.put("mfaVerified", true);
            }
        }

        if (!hasNonNullPayload(payload, "effectiveRoles")) {
            List<String> effectiveRoles = authorities.stream()
                    .filter(authority -> authority.startsWith("ROLE_"))
                    .map(authority -> authority.substring("ROLE_".length()))
                    .distinct()
                    .toList();
            if (!effectiveRoles.isEmpty()) {
                payload.put("effectiveRoles", effectiveRoles);
            }
        }

        if (!hasNonNullPayload(payload, "effectivePermissions")) {
            List<String> effectivePermissions = new ArrayList<>(authorities.stream()
                    .filter(authority -> !authority.toUpperCase(Locale.ROOT).contains("MFA"))
                    .filter(authority -> !authority.startsWith("ROLE_"))
                    .distinct()
                    .toList());

            if (!effectivePermissions.isEmpty()) {
                payload.put("effectivePermissions", effectivePermissions);
            }
        }

        if (!hasNonNullPayload(payload, "authorities")) {
            payload.put("authorities", authorities);
        }
    }

    private void populateStoredSecurityContext(
            String userId,
            RequestInfo requestInfo,
            Map<String, Object> payload) {
        if (securityContextDataStore == null || !StringUtils.hasText(userId) || payload == null) {
            return;
        }
        try {
            // Q-16: a step-up passed in this context is this session's MFA, whoever owns the sign-in: under HOST_OWNED
            // the application's authentication stays as it was, so nothing else tells the next decision of it.
            Instant stepUpPassedAt = securityContextDataStore.getChallengeVerifiedAt(userId,
                    textValue(payload.get("contextBindingHash")));
            if (stepUpPassedAt != null) {
                payload.put("mfaVerified", true);
                putIfAbsent(payload, "challengeVerifiedAt", stepUpPassedAt.toString());
                putIfAbsent(payload, "lastMfaUsedAt", stepUpPassedAt.toString());
            }
            // The user-level MFA mark is not this session's MFA: another session (or device) may have set it. It
            // is carried as its own fact when this session has no MFA of its own.
            if (!Boolean.TRUE.equals(payload.get("mfaVerified"))) {
                Instant lastMfaElsewhere = securityContextDataStore.getLastMfaVerifiedAt(userId);
                if (lastMfaElsewhere != null) {
                    payload.put("recentMfaElsewhereAt", lastMfaElsewhere.toString());
                }
            }
            if (!hasNonNullPayload(payload, "failedLoginAttempts")) {
                // The window ends at the request's own time, the clock the failures are recorded on.
                Instant observedAt = requestInfo != null ? requestInfo.getObservedAt() : null;
                long now = observedAt != null ? observedAt.toEpochMilli() : System.currentTimeMillis();
                int windowMinutes = Math.max(
                        1,
                        securityPlaneProperties.getContext().getLoginFailureWindowMinutes());
                long windowStart = now - windowMinutes * 60_000L;
                // The user's own failures only: other users failing from the same address are not this user's.
                // Unknown stays out of the payload, so the prompt says it is unknown rather than zero.
                Integer failures = securityContextDataStore.findRecentLoginFailures(userId, windowStart, now);
                if (failures != null) {
                    payload.put("failedLoginAttempts", failures);
                    payload.put("failedLoginWindowMinutes", windowMinutes);
                }
            }
        } catch (RuntimeException exception) {
            log.error("Failed to populate stored authentication context: userId={}", userId, exception);
        }
    }

    /** An effect the bridge reported stands: it came from the application's own check, which did finish. */
    private void recordUnfinishedCheck(String checkFailure, Map<String, Object> payload) {
        payload.put("authorizationCheckFailure", checkFailure);
        String existingEffect = textValue(payload.get("authorizationEffect"));
        if (StringUtils.hasText(existingEffect) && !EFFECT_UNKNOWN.equalsIgnoreCase(existingEffect)) {
            payload.putIfAbsent("bridgeAuthorizationEffect", existingEffect);
            payload.putIfAbsent("authorizationEffectProvenance", "BRIDGE_AUTHORIZATION_STAMP");
            return;
        }
        payload.put("authorizationEffect", EFFECT_UNKNOWN);
        payload.put("authorizationEffectProvenance", "METHOD_AUTHORIZATION_UNAVAILABLE");
    }

    private void reconcileAuthorizationDecision(boolean granted, Map<String, Object> payload) {
        String existingEffect = textValue(payload.get("authorizationEffect"));
        if (StringUtils.hasText(existingEffect)) {
            payload.putIfAbsent("bridgeAuthorizationEffect", existingEffect);
        }
        payload.put("methodAuthorizationGranted", granted);
        boolean synthesizedAuthorizationEffect = !StringUtils.hasText(existingEffect)
                || "UNKNOWN".equalsIgnoreCase(existingEffect);
        if (synthesizedAuthorizationEffect) {
            // The effect is the authorization check of the method, not the result of running it; a check made
            // before the method runs says so.
            payload.put("authorizationEffect", granted ? "ALLOW" : "DENY");
            payload.put("authorizationEffectProvenance",
                    METHOD_NOT_RUN.equals(payload.get("methodExecutionOutcome"))
                            ? "METHOD_AUTHORIZATION_BEFORE_EXECUTION"
                            : "METHOD_AUTHORIZATION_CHECK");
            payload.put("authorizationEffectFallbackFrom",
                    StringUtils.hasText(existingEffect) ? existingEffect : "ABSENT");
        } else if (!hasNonNullPayload(payload, "authorizationEffectProvenance")) {
            payload.put("authorizationEffectProvenance", "BRIDGE_AUTHORIZATION_STAMP");
        }
        if (StringUtils.hasText(existingEffect)
                && !"UNKNOWN".equalsIgnoreCase(existingEffect)
                && granted != "ALLOW".equalsIgnoreCase(existingEffect)) {
            payload.put("authorizationDecisionConflict",
                    granted ? "METHOD_GRANTED_WITH_BRIDGE_DENY" : "METHOD_DENIED_WITH_BRIDGE_ALLOW");
        }

        if (!payload.containsKey("bridgeCoverageLevel") || hasNonNullPayload(payload, "bridgeCoverageSummary")) {
            return;
        }

        String coverageLevel = textValue(payload.get("bridgeCoverageLevel"));
        if (StringUtils.hasText(coverageLevel)) {
            payload.put("bridgeCoverageSummary", resolveBridgeCoverageSummary(coverageLevel, extractStringList(payload.get("bridgeMissingContexts"))));
        }
    }

    private String resolveBridgeCoverageSummary(String coverageLevel, List<String> missingContexts) {
        boolean missingAuthorizationAuthorities = missingContexts.contains(MissingBridgeContext.AUTHORIZATION_AUTHORITIES.name());
        boolean missingDelegation = missingContexts.contains(MissingBridgeContext.DELEGATION.name());
        return switch (coverageLevel.trim().toUpperCase(Locale.ROOT)) {
            case "AUTHORIZATION_CONTEXT" -> {
                if (missingAuthorizationAuthorities) {
                    yield "Bridge completeness reached authentication and partial authorization context for the current request.";
                }
                if (missingDelegation) {
                    yield "Bridge completeness reached authentication and authorization context, but delegated execution metadata is incomplete for this request.";
                }
                yield "Bridge completeness reached authentication and authorization context for the current request.";
            }
            case "DELEGATION_CONTEXT" ->
                    "Bridge completeness reached authentication, authorization, and delegated execution context for the current request.";
            case "AUTHENTICATION_ONLY" ->
                    "Bridge completeness reached authentication, but request-level authorization context is still incomplete.";
            default -> "Bridge completeness did not reach an authenticated principal for the current request.";
        };
    }

    private boolean hasNonNullPayload(Map<String, Object> payload, String key) {
        return payload.containsKey(key) && payload.get(key) != null;
    }

    private String bridgeAuthenticationType(Map<String, Object> payload) {
        if (!hasNonNullPayload(payload, "bridgeAuthenticationSource") || !hasNonNullPayload(payload, "authenticationType")) {
            return null;
        }
        String authenticationType = payload.get("authenticationType").toString();
        return StringUtils.hasText(authenticationType) ? authenticationType : null;
    }

    private List<String> sanitizeRoleTokens(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String normalized = normalizeAuthorityValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (isRuntimeActionAuthority(normalized)) {
                continue;
            }
            if (isPermissionAuthorityArtifact(rawValue)) {
                continue;
            }
            if (normalized.startsWith("ROLE_")) {
                normalized = normalized.substring("ROLE_".length());
            }
            if (normalized.contains("/")
                    || normalized.contains(".")
                    || normalized.contains(":")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            values.add(normalized.toUpperCase(Locale.ROOT));
        }
        return List.copyOf(values);
    }

    private List<String> sanitizePermissionTokens(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String authorityValue = normalizeAuthorityValue(rawValue);
            if (!StringUtils.hasText(authorityValue)
                    || authorityValue.startsWith("ROLE_")
                    || isRoleAuthorityArtifact(rawValue)) {
                continue;
            }
            String normalized = normalizePermissionValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (normalized.startsWith("/")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            values.add(normalized);
        }
        return List.copyOf(values);
    }

    private List<String> sanitizeAuthorityTokens(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String normalized = normalizeAuthorityValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (normalized.startsWith("ROLE_")
                    || normalized.startsWith("/")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            values.add(normalized);
        }
        return List.copyOf(values);
    }

    private List<String> sanitizeEvidenceAuthorities(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String normalized = normalizeAuthorityValue(rawValue);
            if (StringUtils.hasText(normalized) && !isRuntimeActionAuthority(normalized)) {
                values.add(normalized);
            }
        }
        return List.copyOf(values);
    }

    private boolean isRuntimeActionAuthority(String rawValue) {
        String normalized = normalizeAuthorityValue(rawValue);
        if (!StringUtils.hasText(normalized)) {
            return false;
        }
        for (ZeroTrustAction action : ZeroTrustAction.values()) {
            if (StringUtils.hasText(action.getGrantedAuthority())
                    && action.getGrantedAuthority().equalsIgnoreCase(normalized)) {
                return true;
            }
        }
        return false;
    }

    private List<String> mergeDistinctStringLists(Object existing, List<String> additions) {
        LinkedHashSet<String> merged = new LinkedHashSet<>(extractStringList(existing));
        merged.addAll(additions);
        return List.copyOf(merged);
    }

    private List<String> extractStringList(Object rawValue) {
        if (rawValue == null) {
            return List.of();
        }
        LinkedHashSet<String> values = new LinkedHashSet<>();
        if (rawValue instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                String normalized = normalizeAuthorityValue(item != null ? item.toString() : null);
                if (StringUtils.hasText(normalized)) {
                    values.add(normalized);
                }
            }
            return List.copyOf(values);
        }
        String text = rawValue.toString();
        if (text.contains(",")) {
            for (String token : text.split(",")) {
                String normalized = normalizeAuthorityValue(token);
                if (StringUtils.hasText(normalized)) {
                    values.add(normalized);
                }
            }
            return List.copyOf(values);
        }
        String normalized = normalizeAuthorityValue(text);
        if (StringUtils.hasText(normalized)) {
            values.add(normalized);
        }
        return List.copyOf(values);
    }

    private String normalizeAuthorityValue(String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return null;
        }
        String value = extractAuthorityLiteral(rawValue);
        value = value != null ? value : rawValue.trim();
        while (!value.isEmpty() && isWrapperChar(value.charAt(0))) {
            value = value.substring(1).trim();
        }
        while (!value.isEmpty() && isWrapperChar(value.charAt(value.length() - 1))) {
            value = value.substring(0, value.length() - 1).trim();
        }
        if (value.isBlank()
                || "null".equalsIgnoreCase(value)
                || value.startsWith("roleId=")
                || value.startsWith("permissionId=")
                || value.startsWith("targetType=")
                || value.startsWith("actionType=")) {
            return null;
        }
        return value;
    }

    private String normalizePermissionValue(String rawValue) {
        String normalized = normalizeAuthorityValue(rawValue);
        if (!StringUtils.hasText(normalized)) {
            return null;
        }
        if (normalized.indexOf('.') < 0
                && normalized.indexOf('/') < 0
                && normalized.indexOf(':') < 0
                && normalized.indexOf('=') < 0
                && normalized.equals(normalized.toUpperCase(Locale.ROOT))
                && normalized.contains("_")) {
            return normalized.toLowerCase(Locale.ROOT).replace('_', '.');
        }
        return normalized;
    }

    private String extractAuthorityLiteral(String rawValue) {
        Matcher quotedMatcher = Pattern.compile("authority='([^']+)'").matcher(rawValue);
        if (quotedMatcher.find()) {
            return quotedMatcher.group(1);
        }
        Matcher plainMatcher = Pattern.compile("authority=([^,}\\]]+)").matcher(rawValue);
        if (plainMatcher.find()) {
            return plainMatcher.group(1).trim();
        }
        return null;
    }

    private boolean isWrapperChar(char value) {
        return value == '[' || value == ']' || value == '{' || value == '}'
                || value == '(' || value == ')' || value == '"' || value == '\'';
    }

    private boolean isPermissionAuthorityArtifact(String rawValue) {
        return rawValue != null && rawValue.contains("PermissionAuthority{");
    }

    private boolean isRoleAuthorityArtifact(String rawValue) {
        return rawValue != null && rawValue.contains("RoleAuthority{");
    }

    private String textValue(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            String text = textValue(value);
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    private void putIfPresent(Map<String, Object> payload, String key, Object value) {
        if (value != null) {
            payload.put(key, value);
        }
    }

    private boolean isClassNameFallback(AuthenticationStamp authenticationStamp, String evidenceStateKey) {
        return BridgeSemanticBoundaryPolicy.CLASS_NAME_FALLBACK.equals(
                authenticationStamp.attributes().get(evidenceStateKey));
    }

    /** Q-17: a request of the console's chain says so, as the subject of its event is told from the payload. */
    private static Map<String, Object> consoleFact(Map<String, Object> payload) {
        Map<String, Object> given = payload != null ? payload : Map.of();
        if (!ConsoleSession.current()) {
            return given;
        }
        Map<String, Object> marked = new HashMap<>(given);
        marked.put("consoleSession", Boolean.TRUE);
        return marked;
    }

    /**
     * A1-6: who answers for an agent request. The agent's sponsor and status come from the registry; the accountable
     * person is the one who delegated the work, or the sponsor when the agent acts on its own or no delegator is known.
     * Later steps send confirmations and notices to that person (A5-2, A5-3). A person's request carries none of these.
     */
    private void putAgentAccountability(Map<String, Object> payload) {
        Object kind = payload.get("executionSubjectKind");
        boolean delegatedAgent = SubjectKind.DELEGATED_AGENT.name().equals(kind);
        if (!delegatedAgent && !SubjectKind.AUTONOMOUS_AGENT.name().equals(kind)) {
            return;
        }
        String agentId = textValue(payload.get("agentId"));
        String sponsorId = null;
        if (agentRegistry != null && agentId != null) {
            try {
                String requestTenant = firstText(payload.get("tenantId"), payload.get("organizationId"));
                // CF-13: a token or account that names no tenant was admitted as the agent's single-tenant registration
                // (AgentTokenClaims.tenant, AgentClientDirectory), so that registration is this agent in a tenant's
                // request too, not an unregistered one; CF-33: also after the engine has recorded its sighting there.
                Optional<AgentRegistration> registration = AgentRegistrations.find(agentRegistry, requestTenant, agentId);
                if (registration.isPresent()) {
                    sponsorId = registration.get().sponsorId();
                    putIfAbsent(payload, "agentSponsorId", sponsorId);
                    payload.putIfAbsent("agentRegistrationStatus", registration.get().status().name());
                    payload.putIfAbsent("agentAllowlisted", registration.get().allowlisted());
                } else {
                    payload.putIfAbsent("agentRegistrationStatus", "UNREGISTERED");
                }
            } catch (RuntimeException ex) {
                log.warn("Agent registry lookup failed for agent {}: {}", agentId, ex.getMessage(), ex);
            }
        }
        String delegatorId = delegatedAgent ? textValue(payload.get("delegatorId")) : null;
        putIfAbsent(payload, "agentAccountableId", delegatorId != null ? delegatorId : sponsorId);
        // docs/agent F-5: the confirmation the accountable person gave for this very request, as the gate kept it.
        AgentConfirmationFacts.current().forEach(payload::putIfAbsent);
    }

    private void putIfAbsent(Map<String, Object> payload, String key, Object value) {
        if (value != null) {
            payload.putIfAbsent(key, value);
        }
    }

    private void populateTestRunMarker(Map<String, Object> payload) {
        if (payload == null) {
            return;
        }
        String runId = currentRequestHeader("X-Contexa-Test-Run-Id");
        if (StringUtils.hasText(runId)) {
            payload.putIfAbsent("testRunId", runId);
        }
    }

    private String currentRequestHeader(String headerName) {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null || attrs.getRequest() == null) {
                return null;
            }
            String value = attrs.getRequest().getHeader(headerName);
            return StringUtils.hasText(value) ? value.trim() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private void putListIfAbsent(Map<String, Object> payload, String key, List<String> values) {
        if (values != null && !values.isEmpty()) {
            payload.putIfAbsent(key, values);
        }
    }

    private Object firstNonNull(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private Protectable resolveProtectable(MethodInvocation methodInvocation) {
        Protectable protectable = AnnotationUtils.findAnnotation(methodInvocation.getMethod(), Protectable.class);
        if (protectable != null) {
            return protectable;
        }

        Object target = methodInvocation.getThis();
        if (target != null) {
            Class<?> targetClass = AopProxyUtils.ultimateTargetClass(target);
            protectable = AnnotationUtils.findAnnotation(
                    AopUtils.getMostSpecificMethod(methodInvocation.getMethod(), targetClass),
                    Protectable.class);
            if (protectable != null) {
                return protectable;
            }
            protectable = AnnotationUtils.findAnnotation(targetClass, Protectable.class);
            if (protectable != null) {
                return protectable;
            }
        }

        return AnnotationUtils.findAnnotation(methodInvocation.getMethod().getDeclaringClass(), Protectable.class);
    }
}

