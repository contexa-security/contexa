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
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import io.contexa.contexacore.verification.runtime.OfficialVerificationProbeHeaders;
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

    public void publishMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        ZeroTrustSpringEvent event = buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                granted,
                denialReason
        );
        eventPublisher.publishEvent(event);
    }

    public ZeroTrustSpringEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {

        RequestInfo requestInfo = extractRequestInfoFromContext();
        String effectiveUserId = resolveEffectiveUserId(authentication);
        String methodResource = methodInvocation.getMethod().getDeclaringClass().getSimpleName()
                + "." + methodInvocation.getMethod().getName();
        String resource = (requestInfo != null && requestInfo.getRequestUri() != null)
                ? requestInfo.getRequestUri()
                : methodResource;

        Map<String, Object> payload = new HashMap<>();
        payload.put("granted", granted);
        payload.put("denialReason", denialReason != null ? denialReason : "");
        payload.put("methodName", methodInvocation.getMethod().getName());
        payload.put("className", methodInvocation.getMethod().getDeclaringClass().getName());

        Protectable protectable = resolveProtectable(methodInvocation);
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
            payload.put("requestId", requestInfo.getRequestId());
            payload.put("correlationId", requestInfo.getRequestId());
            payload.put("contextBindingHash", requestInfo.getContextBindingHash());
            payload.put("clientIp", requestInfo.getClientIp());
            payload.put("userAgent", requestInfo.getUserAgent());
            payload.put("scenario", requestInfo.getScenario());
            payload.put("demoRunId", requestInfo.getDemoRunId());
            payload.put("demoPhase", requestInfo.getDemoPhase());
            if (requestInfo.getRoundKey() != null) {
                payload.put("roundKey", requestInfo.getRoundKey());
            }
            if (requestInfo.getBehaviorPhase() != null) {
                payload.put("behaviorPhase", requestInfo.getBehaviorPhase());
            }
            if (requestInfo.getAnomalySignal() != null) {
                payload.put("anomalySignal", requestInfo.getAnomalySignal());
                payload.put("anomalySignalSource", requestInfo.getAnomalySignalSource());
            }
            if (requestInfo.getPqaPromptFaultScenario() != null) {
                OfficialVerificationProbeHeaders.authorizeFaultMetadata(
                        payload, requestInfo.getPqaPromptFaultScenario());
                payload.put("pqaPromptFaultSource", "OFFICIAL_VERIFICATION_INTERNAL");
            }
            if (Boolean.TRUE.equals(requestInfo.getPqaPromptFaultRejected())) {
                payload.put("pqaPromptFaultRejected", true);
                payload.put("pqaPromptFaultRejectedSource", requestInfo.getPqaPromptFaultRejectedSource());
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
                payload.put("travelDistanceKm", requestInfo.getTravelDistanceKm());
                payload.put("travelElapsedMinutes", requestInfo.getTravelElapsedMinutes());
                payload.put("previousLocation", requestInfo.getPreviousLocation());
            }
            promoteOfficialContextFields(requestInfo, payload);
        }

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
        Object managedResourceUrl =
                attributes.getRequest().getAttribute("officialVerification.protectableResourceUrl");
        if (managedResourceUrl != null && StringUtils.hasText(String.valueOf(managedResourceUrl))) {
            return String.valueOf(managedResourceUrl).trim();
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
                String requestedUserId = OfficialVerificationRequestContext.resolveUserId(attrs.getRequest());
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
            putIfAbsent(payload, "principalType", authenticationStamp.principalType());
            putIfAbsent(payload, "authenticationType", authenticationStamp.authenticationType());
            putIfAbsent(payload, "authenticationAssurance", authenticationStamp.authenticationAssurance());
            putIfAbsent(payload, "mfaVerified", authenticationStamp.mfaCompleted());
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
        }

        AuthorizationStamp authorizationStamp = bridgeResolutionResult.authorizationStamp();
        if (authorizationStamp != null) {
            putIfAbsent(payload, "bridgeAuthorizationSource", authorizationStamp.decisionSource());
            putIfAbsent(payload, "authorizationEffect", authorizationStamp.effect().name());
            putIfAbsent(payload, "privileged", authorizationStamp.privileged());
            putIfAbsent(payload, "policyId", authorizationStamp.policyId());
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
            putIfAbsent(payload, "approvalRequired", delegationStamp.approvalRequired());
            putIfAbsent(payload, "privilegedExportAllowed", delegationStamp.privilegedExportAllowed());
            putIfAbsent(payload, "containmentOnly", delegationStamp.containmentOnly());
            if (!delegationStamp.allowedOperations().isEmpty()) {
                payload.putIfAbsent("allowedOperations", delegationStamp.allowedOperations());
            }
            if (!delegationStamp.allowedResources().isEmpty()) {
                payload.putIfAbsent("allowedResources", delegationStamp.allowedResources());
            }
        }
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

    private void promoteOfficialContextFields(RequestInfo requestInfo, Map<String, Object> payload) {
        if (requestInfo == null || requestInfo.getOfficialContextFields() == null || requestInfo.getOfficialContextFields().isEmpty()) {
            return;
        }
        requestInfo.getOfficialContextFields().forEach((key, value) -> putIfAbsent(payload, key, value));
    }

    private void populateAuthenticationFallback(Authentication authentication, Map<String, Object> payload) {
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
            boolean hasMfaAuthority = authorities.stream()
                    .anyMatch(authority -> authority.toUpperCase().contains("MFA"));
            payload.put("authMethod", hasMfaAuthority ? "mfa" : "password");
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
            if (!hasNonNullPayload(payload, "mfaVerified")) {
                payload.put("mfaVerified", securityContextDataStore.isMfaVerified(userId));
            }
            if (!hasNonNullPayload(payload, "failedLoginAttempts")) {
                long now = System.currentTimeMillis();
                int windowMinutes = Math.max(
                        1,
                        securityPlaneProperties.getContext().getLoginFailureWindowMinutes());
                long windowStart = now - windowMinutes * 60_000L;
                String clientIp = requestInfo != null ? requestInfo.getClientIp() : null;
                payload.put(
                        "failedLoginAttempts",
                        securityContextDataStore.getRecentLoginFailureCount(
                                userId,
                                clientIp,
                                windowStart,
                                now));
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
            payload.put("authorizationEffect", granted ? "ALLOW" : "DENY");
            payload.put("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
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

