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

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
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
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class ZeroTrustEventPublisher {

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

    /** The event of an authorization check made before the method runs (a synchronous decision). */
    public ZeroTrustSpringEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        return buildMethodAuthorizationEvent(methodInvocation, authentication, granted, denialReason, METHOD_NOT_RUN, null);
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

        RequestInfo requestInfo = extractRequestInfoFromContext();
        String effectiveUserId = resolveEffectiveUserId(authentication);
        String methodResource = methodInvocation != null
                ? methodInvocation.getMethod().getDeclaringClass().getSimpleName() + "." + methodInvocation.getMethod().getName()
                : "URL_POLICY";
        String resource = (requestInfo != null && requestInfo.getRequestUri() != null)
                ? requestInfo.getRequestUri()
                : methodResource;

        Map<String, Object> payload = new HashMap<>();
        payload.put("granted", granted);
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
        reconcileAuthorizationDecision(granted, payload);
        putIfAbsent(payload, "decisionBoundaryMode", securityZeroTrustMode());

        if (actionRedisRepository != null && authentication != null) {
            ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(effectiveUserId);
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

        Map<String, Object> effectivePayload = CanonicalExecutionEventMetadataSupport.enrich(payload != null ? payload : Map.of());

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
        }
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
                    .anyMatch(authority -> authority.toUpperCase().contains("MFA"));
            if (hasMfaAuthority) {
                payload.put("authMethod", "mfa");
            }
        }

        if (!hasNonNullPayload(payload, "mfaVerified")) {
            boolean hasMfaAuthority = authorities.stream()
                    .anyMatch(authority -> authority.toUpperCase().contains("MFA"));
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
                    .filter(authority -> !authority.toUpperCase().contains("MFA"))
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

