package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

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

        if (requestInfo != null) {
            payload.put("httpUri", requestInfo.getRequestUri());
            payload.put("requestPath", requestInfo.getRequestUri());
            payload.put("httpMethod", requestInfo.getMethod());
            payload.put("isNewSession", requestInfo.getIsNewSession());
            payload.put("isNewUser", requestInfo.getIsNewUser());
            payload.put("isNewDevice", requestInfo.getIsNewDevice());
            payload.put("recentRequestCount", requestInfo.getRecentRequestCount());
            payload.put("failedLoginAttempts", requestInfo.getFailedLoginAttempts());
            payload.put("baselineConfidence", requestInfo.getBaselineConfidence());
            payload.put("isSensitiveResource", requestInfo.getIsSensitiveResource());
            payload.put("mfaVerified", requestInfo.getMfaVerified());
            payload.put("userRoles", requestInfo.getUserRoles());
            populateBridgePayload(requestInfo, payload);

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
        }

        if (actionRedisRepository != null && authentication != null) {
            ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(authentication.getName());
            if (currentAction != null) {
                payload.put("action", currentAction.name());
            }
        }

        return build(
                ZeroTrustEventCategory.AUTHORIZATION,
                ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD,
                authentication != null ? authentication.getName() : null,
                requestInfo != null ? requestInfo.getSessionId() : null,
                requestInfo != null ? requestInfo.getClientIp() : null,
                requestInfo != null ? requestInfo.getUserAgent() : null,
                resource,
                payload
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
                payload
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
            Map<String, Object> payload) {

        return ZeroTrustSpringEvent.builder(this)
                .category(category)
                .eventType(eventType)
                .userId(userId)
                .sessionId(sessionId)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .resource(resource)
                .eventTimestamp(Instant.now())
                .payload(payload != null ? payload : Map.of())
                .build();
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
            putIfPresent(payload, "bridgeAuthenticationSource", authenticationStamp.authenticationSource());
            putIfPresent(payload, "principalType", authenticationStamp.principalType());
            putIfPresent(payload, "authenticationType", authenticationStamp.authenticationType());
            putIfPresent(payload, "authenticationAssurance", authenticationStamp.authenticationAssurance());
            putIfPresent(payload, "mfaVerified", authenticationStamp.mfaCompleted());
            if (!authenticationStamp.authorities().isEmpty()) {
                payload.put("authorities", authenticationStamp.authorities());
            }
            putIfPresent(payload, "organizationId", authenticationStamp.attributes().get("organizationId"));
            putIfPresent(payload, "orgId", authenticationStamp.attributes().get("orgId"));
            putIfPresent(payload, "department", authenticationStamp.attributes().get("department"));
        }

        AuthorizationStamp authorizationStamp = bridgeResolutionResult.authorizationStamp();
        if (authorizationStamp != null) {
            putIfPresent(payload, "bridgeAuthorizationSource", authorizationStamp.decisionSource());
            payload.put("authorizationEffect", authorizationStamp.effect().name());
            putIfPresent(payload, "privileged", authorizationStamp.privileged());
            putIfPresent(payload, "policyId", authorizationStamp.policyId());
            if (!authorizationStamp.scopeTags().isEmpty()) {
                payload.put("scopeTags", authorizationStamp.scopeTags());
            }
            if (!authorizationStamp.effectiveRoles().isEmpty()) {
                payload.put("effectiveRoles", authorizationStamp.effectiveRoles());
            }
            if (!authorizationStamp.effectiveAuthorities().isEmpty()) {
                payload.put("effectivePermissions", authorizationStamp.effectiveAuthorities());
                payload.put("authorities", authorizationStamp.effectiveAuthorities());
            }
        }

        DelegationStamp delegationStamp = bridgeResolutionResult.delegationStamp();
        if (delegationStamp != null && delegationStamp.delegated()) {
            putIfPresent(payload, "bridgeDelegationSource", delegationStamp.attributes().get("delegationResolver"));
            payload.put("delegated", true);
            putIfPresent(payload, "agentId", delegationStamp.agentId());
            putIfPresent(payload, "objectiveId", delegationStamp.objectiveId());
            putIfPresent(payload, "objectiveFamily", delegationStamp.objectiveFamily());
            putIfPresent(payload, "objectiveSummary", delegationStamp.objectiveSummary());
            putIfPresent(payload, "approvalRequired", delegationStamp.approvalRequired());
            putIfPresent(payload, "privilegedExportAllowed", delegationStamp.privilegedExportAllowed());
            putIfPresent(payload, "containmentOnly", delegationStamp.containmentOnly());
            if (!delegationStamp.allowedOperations().isEmpty()) {
                payload.put("allowedOperations", delegationStamp.allowedOperations());
            }
            if (!delegationStamp.allowedResources().isEmpty()) {
                payload.put("allowedResources", delegationStamp.allowedResources());
            }
        }
    }

    private void putIfPresent(Map<String, Object> payload, String key, Object value) {
        if (value != null) {
            payload.put(key, value);
        }
    }
}
