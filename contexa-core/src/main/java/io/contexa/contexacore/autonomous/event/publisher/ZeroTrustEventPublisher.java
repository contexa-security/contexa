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
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
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

    @Autowired(required = false)
    private ZeroTrustActionRepository actionRedisRepository;

    public ZeroTrustEventPublisher(
            ApplicationEventPublisher eventPublisher,
            TieredStrategyProperties properties) {
        this.eventPublisher = eventPublisher;
        this.properties = properties;
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

    public void publishAuthenticationFailure(
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            Map<String, Object> payload) {

        publish(
                ZeroTrustEventCategory.AUTHENTICATION,
                ZeroTrustSpringEvent.TYPE_AUTHENTICATION_FAILURE,
                userId,
                sessionId,
                clientIp,
                userAgent,
                null,
                payload
        );

    }

    public void publishPreProtectableThreat(String userId, Map<String, Object> payload) {
        RequestInfo requestInfo = extractRequestInfoFromContext();
        Map<String, Object> mergedPayload = new HashMap<>();
        if (payload != null) {
            mergedPayload.putAll(payload);
        }
        if (requestInfo != null) {
            putIfAbsent(mergedPayload, "requestPath", requestInfo.getRequestUri());
            putIfAbsent(mergedPayload, "requestUri", requestInfo.getRequestUri());
            putIfAbsent(mergedPayload, "httpMethod", requestInfo.getMethod());
            putIfAbsent(mergedPayload, "requestId", requestInfo.getRequestId());
            putIfAbsent(mergedPayload, "correlationId", requestInfo.getRequestId());
            putIfAbsent(mergedPayload, "clientIp", requestInfo.getClientIp());
            putIfAbsent(mergedPayload, "userAgent", requestInfo.getUserAgent());
            putIfAbsent(mergedPayload, "resourceSensitivity", requestInfo.getResourceSensitivity());
            putIfAbsent(mergedPayload, "mfaVerified", requestInfo.getMfaVerified());
            putIfAbsent(mergedPayload, "previousPath", requestInfo.getPreviousPath());
            putIfAbsent(mergedPayload, "lastRequestIntervalMs", requestInfo.getLastRequestIntervalMs());
            putIfAbsent(mergedPayload, "recentRequestCount", requestInfo.getRecentRequestCount());
            putIfAbsent(mergedPayload, "failedLoginAttempts", requestInfo.getFailedLoginAttempts());
            putIfAbsent(mergedPayload, "isNewDevice", requestInfo.getIsNewDevice());
            putIfAbsent(mergedPayload, "impossibleTravel", requestInfo.getImpossibleTravel());
            promoteOfficialContextFields(requestInfo, mergedPayload);
            populateBridgePayload(requestInfo, mergedPayload);
        }
        if (actionRedisRepository != null && userId != null && !mergedPayload.containsKey("action")) {
            ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(userId);
            if (currentAction != null) {
                mergedPayload.put("action", currentAction.name());
            }
        }

        publish(
                ZeroTrustEventCategory.THREAT,
                ZeroTrustSpringEvent.TYPE_PRE_PROTECTABLE_REDLINE,
                userId,
                requestInfo != null ? requestInfo.getSessionId() : null,
                requestInfo != null ? requestInfo.getClientIp() : null,
                requestInfo != null ? requestInfo.getUserAgent() : null,
                requestInfo != null ? requestInfo.getRequestUri() : null,
                mergedPayload
        );
    }

    public void publishMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        if (shouldSuppressMethodAuthorizationEvent()) {
            log.debug("[ZeroTrustEventPublisher] Suppressing same-request METHOD authorization event after pre-trigger analysis start");
            return;
        }
        markProtectableAnalysisStarted();
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
            payload.put("protectableResourceId", protectable.resourceId());
            payload.put("protectableResourceUrl", protectable.resourceUrl());
            payload.put("protectableHttpMethod", protectable.httpMethod());
            payload.put("protectableVerificationRequired", protectable.verificationRequired());
            payload.put("protectableMethod", methodInvocation.getMethod().getDeclaringClass().getName()
                    + "." + methodInvocation.getMethod().getName());
        }

        if (requestInfo != null) {
            payload.put("httpUri", requestInfo.getRequestUri());
            payload.put("requestPath", requestInfo.getRequestUri());
            payload.put("requestUri", requestInfo.getRequestUri());
            payload.put("httpMethod", requestInfo.getMethod());
            payload.put("requestId", requestInfo.getRequestId());
            payload.put("correlationId", requestInfo.getRequestId());
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
            }
            if (requestInfo.getPqaPromptFaultScenario() != null) {
                payload.put("pqaPromptFaultEnabled", true);
                payload.put("pqaPromptFaultScenario", requestInfo.getPqaPromptFaultScenario());
                payload.put("pqaPromptFaultSource", "REQUEST");
            }
            if (requestInfo.getPromptBudgetProfile() != null) {
                payload.put("promptBudgetProfile", requestInfo.getPromptBudgetProfile());
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
                payload.put("requestedResourceId", requestInfo.getResourceId());
                payload.put("protectedResourceId", requestInfo.getResourceId());
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
            populateHcadPreTriggerObservationPayload(payload);

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
        reconcileAuthorizationDecision(granted, payload);

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

    private boolean shouldSuppressMethodAuthorizationEvent() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return false;
            }
            HttpServletRequest request = attrs.getRequest();
            return Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED));
        } catch (Exception e) {
            log.error("Failed to resolve pre-trigger suppression state", e);
            return false;
        }
    }

    private void markProtectableAnalysisStarted() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                attrs.getRequest().setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_TRIGGER_STARTED, true);
            }
        } catch (Exception e) {
            log.error("Failed to mark Protectable analysis lifecycle state", e);
        }
    }

    private void populateHcadPreTriggerObservationPayload(Map<String, Object> payload) {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return;
            }
            HttpServletRequest request = attrs.getRequest();
            if (!Boolean.TRUE.equals(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EVALUATED))) {
                return;
            }
            payload.put(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_MODE,
                    HcadPreProtectablePromotionAttributes.METADATA_MODE);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_SCORE,
                    HcadPreProtectablePromotionAttributes.METADATA_SCORE);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_EARLY_ANALYSIS_SCORE,
                    HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_BAND,
                    HcadPreProtectablePromotionAttributes.METADATA_BAND);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE,
                    HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_ANCHOR_SIGNALS,
                    HcadPreProtectablePromotionAttributes.METADATA_ANCHOR_SIGNALS);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_CORROBORATING_SIGNALS,
                    HcadPreProtectablePromotionAttributes.METADATA_CORROBORATING_SIGNALS);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_REASON_CODES,
                    HcadPreProtectablePromotionAttributes.METADATA_REASON_CODES);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_SUMMARY,
                    HcadPreProtectablePromotionAttributes.METADATA_SUMMARY);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_VERSION,
                    HcadPreProtectablePromotionAttributes.METADATA_VERSION);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_RAW_SIGNALS,
                    HcadPreProtectablePromotionAttributes.METADATA_RAW_SIGNALS);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_PROVENANCE,
                    HcadPreProtectablePromotionAttributes.METADATA_PROVENANCE);
            copyRequestAttribute(request, payload,
                    HcadPreProtectablePromotionAttributes.REQUEST_IGNORED_INPUTS,
                    HcadPreProtectablePromotionAttributes.METADATA_IGNORED_INPUTS);
            copyRequestAttribute(request, payload,
                    PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID,
                    "hcadEvaluationId");
        } catch (Exception e) {
            log.error("Failed to copy HCAD pre-trigger observation metadata", e);
        }
    }

    private void copyRequestAttribute(
            HttpServletRequest request,
            Map<String, Object> payload,
            String requestAttributeName,
            String metadataName) {
        Object value = request.getAttribute(requestAttributeName);
        if (value != null) {
            payload.putIfAbsent(metadataName, value);
        }
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
                payload.put("authorities", mergeDistinctStringLists(payload.get("authorities"), authenticationStamp.authorities()));
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
        List<String> authorities = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority != null ? grantedAuthority.getAuthority() : null)
                .filter(authority -> authority != null && !authority.isBlank())
                .distinct()
                .toList();
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
            if (effectivePermissions.isEmpty()) {
                effectivePermissions.addAll(authorities.stream()
                        .filter(authority -> !authority.toUpperCase().contains("MFA"))
                        .distinct()
                        .toList());
            }
            if (!effectivePermissions.isEmpty()) {
                payload.put("effectivePermissions", effectivePermissions);
            }
        }

        if (!hasNonNullPayload(payload, "authorities")) {
            payload.put("authorities", authorities);
        }
    }

    private void reconcileAuthorizationDecision(boolean granted, Map<String, Object> payload) {
        String existingEffect = textValue(payload.get("authorizationEffect"));
        boolean synthesizedAuthorizationEffect = !StringUtils.hasText(existingEffect)
                || "UNKNOWN".equalsIgnoreCase(existingEffect);
        if (synthesizedAuthorizationEffect) {
            payload.put("authorizationEffect", granted ? "ALLOW" : "DENY");
            payload.put("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
        } else if (!hasNonNullPayload(payload, "authorizationEffectProvenance")) {
            payload.put("authorizationEffectProvenance", "BRIDGE_AUTHORIZATION_STAMP");
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
            String normalized = normalizePermissionValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (normalized.startsWith("ROLE_")
                    || normalized.startsWith("/")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            if (isRoleAuthorityArtifact(rawValue)) {
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
















