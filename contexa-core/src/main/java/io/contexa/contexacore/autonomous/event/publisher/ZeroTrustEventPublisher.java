package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ZeroTrustEventPublisher {

    private final ApplicationEventPublisher eventPublisher;
    private final TieredStrategyProperties properties;

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

    public void publishWebAuthorization(
            Authentication authentication,
            HttpServletRequest request,
            AuthorizationDecision decision) {

        RequestInfo requestInfo = RequestInfoExtractor.extract(request, getSecurity());

        Map<String, Object> payload = new HashMap<>();
        payload.put("httpMethod", requestInfo != null ? requestInfo.getMethod() : null);
        payload.put("granted", decision.isGranted());
        payload.put("requestInfo", requestInfo);
        payload.put("queryString", requestInfo != null ? requestInfo.getQueryString() : null);
        payload.put("secure", requestInfo != null && requestInfo.isSecure());

        if (requestInfo != null) {
            payload.put("isNewSession", requestInfo.getIsNewSession());
            payload.put("isNewUser", requestInfo.getIsNewUser());
            payload.put("isNewDevice", requestInfo.getIsNewDevice());
            payload.put("recentRequestCount", requestInfo.getRecentRequestCount());
        }

        publish(
                ZeroTrustEventCategory.AUTHORIZATION,
                ZeroTrustSpringEvent.TYPE_AUTHORIZATION_WEB,
                authentication != null ? authentication.getName() : null,
                requestInfo != null ? requestInfo.getSessionId() : null,
                requestInfo != null ? requestInfo.getClientIp() : null,
                requestInfo != null ? requestInfo.getUserAgent() : null,
                requestInfo != null ? requestInfo.getRequestUri() : null,
                payload
        );

    }

    public void publishMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {

        RequestInfo requestInfo = extractRequestInfoFromContext();
        String resource = methodInvocation.getMethod().getDeclaringClass().getSimpleName()
                + "." + methodInvocation.getMethod().getName();

        Map<String, Object> payload = new HashMap<>();
        payload.put("granted", granted);
        payload.put("denialReason", denialReason != null ? denialReason : "");
        payload.put("methodName", methodInvocation.getMethod().getName());
        payload.put("className", methodInvocation.getMethod().getDeclaringClass().getName());

        if (requestInfo != null) {
            payload.put("httpUri", requestInfo.getRequestUri());
            payload.put("httpMethod", requestInfo.getMethod());
            payload.put("isNewSession", requestInfo.getIsNewSession());
            payload.put("isNewUser", requestInfo.getIsNewUser());
            payload.put("isNewDevice", requestInfo.getIsNewDevice());
            payload.put("recentRequestCount", requestInfo.getRecentRequestCount());
        }

        publish(
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

        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.
                builder(this)
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

        eventPublisher.publishEvent(event);

    }

    public void publishCustom(String customEventType, String userId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.CUSTOM, customEventType, userId, payload);
    }

    public void publishCustom(
            String customEventType,
            String userId,
            String sessionId,
            String clientIp,
            String resource,
            Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.CUSTOM, customEventType, userId, sessionId, clientIp, null, resource, payload);
    }

    public void publishThreat(String threatType, String userId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.THREAT, threatType, userId, payload);
    }

    public void publishAnomaly(String userId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.THREAT, ZeroTrustSpringEvent.TYPE_THREAT_ANOMALY, userId, payload);
    }

    public void publishSessionCreated(String userId, String sessionId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.SESSION, ZeroTrustSpringEvent.TYPE_SESSION_CREATED,
                userId, sessionId, null, null, null, payload);
    }

    public void publishSessionExpired(String userId, String sessionId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.SESSION, ZeroTrustSpringEvent.TYPE_SESSION_EXPIRED,
                userId, sessionId, null, null, null, payload);
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
        }
        return null;
    }
}
