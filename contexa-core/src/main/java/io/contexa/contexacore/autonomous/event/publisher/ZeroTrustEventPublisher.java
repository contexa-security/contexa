package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
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
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Zero Trust 공통 이벤트 발행 모듈
 *
 * AI Native v13.0: 이벤트 기반 Zero Trust 아키텍처
 *
 * 설계 목표:
 * 1. 플러그 앤 플레이: 애플리케이션에서 이 모듈만 주입하면 Zero Trust 작동
 * 2. 무제한 확장: 새 이벤트 타입 추가 시 이 클래스 수정 없이 바로 사용
 * 3. 직관적 API: 용도별 편의 메서드 + 범용 메서드 제공
 *
 * 사용 예시:
 * <pre>
 * // 1. 편의 메서드 (기존 플랫폼 이벤트)
 * zeroTrustEventPublisher.publishWebAuthorization(authentication, request, decision);
 *
 * // 2. 범용 메서드 (확장)
 * zeroTrustEventPublisher.publish(THREAT, "SQL_INJECTION", userId, threatData);
 *
 * // 3. 커스텀 이벤트 (애플리케이션 정의)
 * zeroTrustEventPublisher.publishCustom("PAYMENT_FRAUD", userId, fraudData);
 * </pre>
 *
 * @author contexa
 * @since 4.0.0
 */
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

    // ========== 1. 편의 메서드: 인증 이벤트 ==========

    /**
     * 인증 성공 이벤트 발행
     *
     * @param userId 사용자 ID
     * @param sessionId 세션 ID
     * @param clientIp 클라이언트 IP
     * @param userAgent User-Agent
     * @param payload 인증 상세 정보 (trustScore, riskLevel, mfaCompleted 등)
     */
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

        log.debug("[ZeroTrustEventPublisher] Authentication success event published - user: {}", userId);
    }

    /**
     * 인증 실패 이벤트 발행
     *
     * @param userId 사용자 ID (시도된 사용자)
     * @param sessionId 세션 ID
     * @param clientIp 클라이언트 IP
     * @param userAgent User-Agent
     * @param payload 실패 상세 정보 (failureReason, failureCount, bruteForceDetected 등)
     */
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

        log.debug("[ZeroTrustEventPublisher] Authentication failure event published - user: {}", userId);
    }

    // ========== 2. 편의 메서드: Web 인가 이벤트 ==========

    /**
     * Web 인가 결정 이벤트 발행
     *
     * @param authentication 인증 정보
     * @param request HTTP 요청
     * @param decision 인가 결정
     */
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

        // Zero Trust 신호
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

        log.debug("[ZeroTrustEventPublisher] Web authorization event published - user: {}, resource: {}, granted: {}",
                authentication != null ? authentication.getName() : "anonymous",
                requestInfo != null ? requestInfo.getRequestUri() : "unknown",
                decision.isGranted());
    }

    // ========== 2. 편의 메서드: Method 인가 이벤트 ==========

    /**
     * Method 인가 결정 이벤트 발행
     *
     * @param methodInvocation 메서드 호출 정보
     * @param authentication 인증 정보
     * @param granted 인가 여부
     * @param denialReason 거부 사유 (거부된 경우)
     */
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

        // HTTP 요청 정보 (있는 경우)
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

        log.debug("[ZeroTrustEventPublisher] Method authorization event published - user: {}, method: {}, granted: {}",
                authentication != null ? authentication.getName() : "anonymous",
                resource,
                granted);
    }

    // ========== 3. 범용 메서드: 카테고리 + 타입 (확장용 핵심 API) ==========

    /**
     * 임의의 이벤트 발행 - 애플리케이션에서 자유롭게 사용
     *
     * 사용 예시:
     * - 기본: publish(AUTHORIZATION, "WEB", userId, data)
     * - 확장: publish(THREAT, "SQL_INJECTION", userId, sqlData)
     * - 확장: publish(CUSTOM, "MY_AUDIT_EVENT", userId, auditData)
     *
     * @param category 이벤트 카테고리 (핸들러 라우팅용)
     * @param eventType 이벤트 타입 (문자열 - 자유롭게 정의)
     * @param userId 사용자 ID
     * @param payload 이벤트 데이터
     */
    public void publish(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            Map<String, Object> payload) {

        publish(category, eventType, userId, null, null, null, null, payload);
    }

    // ========== 4. 완전 범용 메서드: 모든 필드 지정 ==========

    /**
     * 모든 필드를 지정하여 이벤트 발행
     *
     * @param category 이벤트 카테고리
     * @param eventType 이벤트 타입
     * @param userId 사용자 ID
     * @param sessionId 세션 ID
     * @param clientIp 클라이언트 IP
     * @param userAgent User-Agent
     * @param resource 리소스 (URL, 메서드명 등)
     * @param payload 이벤트 데이터
     */
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

        log.debug("[ZeroTrustEventPublisher] Event published - category: {}, type: {}, user: {}",
                category, eventType, userId);
    }

    // ========== 5. CUSTOM 카테고리 전용 편의 메서드 ==========

    /**
     * 애플리케이션 정의 커스텀 이벤트 발행
     * - 새로운 이벤트 타입을 코드 변경 없이 바로 사용 가능
     *
     * 사용 예시:
     * - publishCustom("PAYMENT_COMPLETED", userId, paymentData)
     * - publishCustom("DATA_EXPORT_REQUEST", userId, exportData)
     * - publishCustom("SENSITIVE_OPERATION", userId, operationData)
     *
     * @param customEventType 커스텀 이벤트 타입
     * @param userId 사용자 ID
     * @param payload 이벤트 데이터
     */
    public void publishCustom(String customEventType, String userId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.CUSTOM, customEventType, userId, payload);
    }

    /**
     * 애플리케이션 정의 커스텀 이벤트 발행 (모든 필드)
     *
     * @param customEventType 커스텀 이벤트 타입
     * @param userId 사용자 ID
     * @param sessionId 세션 ID
     * @param clientIp 클라이언트 IP
     * @param resource 리소스
     * @param payload 이벤트 데이터
     */
    public void publishCustom(
            String customEventType,
            String userId,
            String sessionId,
            String clientIp,
            String resource,
            Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.CUSTOM, customEventType, userId, sessionId, clientIp, null, resource, payload);
    }

    // ========== 6. 위협 탐지 이벤트 편의 메서드 ==========

    /**
     * 위협 탐지 이벤트 발행
     *
     * @param threatType 위협 유형 (예: "SQL_INJECTION", "XSS_ATTEMPT")
     * @param userId 사용자 ID
     * @param payload 위협 상세 정보
     */
    public void publishThreat(String threatType, String userId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.THREAT, threatType, userId, payload);
    }

    /**
     * 이상 행위 탐지 이벤트 발행
     *
     * @param userId 사용자 ID
     * @param payload 이상 행위 상세 정보
     */
    public void publishAnomaly(String userId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.THREAT, ZeroTrustSpringEvent.TYPE_THREAT_ANOMALY, userId, payload);
    }

    // ========== 7. 세션 이벤트 편의 메서드 ==========

    /**
     * 세션 생성 이벤트 발행
     */
    public void publishSessionCreated(String userId, String sessionId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.SESSION, ZeroTrustSpringEvent.TYPE_SESSION_CREATED,
                userId, sessionId, null, null, null, payload);
    }

    /**
     * 세션 만료 이벤트 발행
     */
    public void publishSessionExpired(String userId, String sessionId, Map<String, Object> payload) {
        publish(ZeroTrustEventCategory.SESSION, ZeroTrustSpringEvent.TYPE_SESSION_EXPIRED,
                userId, sessionId, null, null, null, payload);
    }

    // ========== Private 메서드 ==========

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
            log.debug("[ZeroTrustEventPublisher] Failed to extract request info from context: {}", e.getMessage());
        }
        return null;
    }
}
