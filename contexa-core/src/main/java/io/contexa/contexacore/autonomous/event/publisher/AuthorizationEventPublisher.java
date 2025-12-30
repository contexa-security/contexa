package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 통합 인가 이벤트 발행자
 * 
 * 모든 인가 관련 이벤트를 Spring Events로 발행합니다.
 * - CustomDynamicAuthorizationManager: 웹 요청 인가
 * - AuthorizationManagerMethodInterceptor: @Protectable 메서드 인가
 * 
 * 발행된 이벤트는 ZeroTrustAuthenticationEventListener가 수신하여
 */
@Slf4j
@RequiredArgsConstructor
public class AuthorizationEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    /**
     * 웹 요청에 대한 인가 결정 이벤트 발행 (동기 진입점)
     *
     * 동기 컨텍스트에서 request 정보를 먼저 추출한 후 비동기 처리.
     * Tomcat request 객체 재활용(recycle) 문제 방지.
     */
    public void publishWebAuthorizationDecision(
            Authentication authentication,
            HttpServletRequest request,
            AuthorizationDecision decision,
            TrustAssessment trustAssessment) {

        // 동기 컨텍스트에서 request 정보 추출 (핵심!)
        // @Async 비동기 스레드에서 request 객체 접근 시 IllegalStateException 방지
        RequestInfo requestInfo = RequestInfo.from(request);

        // 이벤트 발행 플래그 설정 (동기 컨텍스트에서 수행)
        request.setAttribute("security.event.published", true);

        // 추출된 정보로 비동기 처리
        publishWebAuthorizationDecisionAsyncInternal(authentication, requestInfo, decision, trustAssessment);
    }

    /**
     * 내부 비동기 처리 메서드 (RequestInfo 사용)
     *
     * HttpServletRequest 대신 불변 RequestInfo DTO를 받아 처리.
     * Tomcat request 객체 재활용 문제 완전 방지.
     */
    @Async("securityEventExecutor")
    void publishWebAuthorizationDecisionAsyncInternal(
            Authentication authentication,
            RequestInfo requestInfo,
            AuthorizationDecision decision,
            TrustAssessment trustAssessment) {

        try {
            AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder =
                    AuthorizationDecisionEvent.builder();

            // 기본 정보 설정 (RequestInfo에서 추출)
            String userName = authentication != null ? authentication.getName() : null;
            builder.eventId(UUID.randomUUID().toString())
                    .timestamp(Instant.now())
                    .eventType("WEB_REQUEST")
                    .principal(userName != null ? userName : "anonymous")
                    .userId(userName)
                    .resource(requestInfo.getRequestUri())
                    .action(requestInfo.getMethod())
                    .httpMethod(requestInfo.getMethod())
                    .result(decision.isGranted() ?
                            AuthorizationDecisionEvent.AuthorizationResult.ALLOWED :
                            AuthorizationDecisionEvent.AuthorizationResult.DENIED)
                    .clientIp(requestInfo.getClientIp())
                    .userAgent(requestInfo.getUserAgent())
                    .sessionId(requestInfo.getSessionId())
                    .requestId(requestInfo.getRequestId());

            // 사용자 정보 추가
            if (authentication != null && authentication.getPrincipal() != null) {
                builder.userId(authentication.getName());
                builder.organizationId(extractOrganizationId(authentication));
            }

            // AI 평가 정보 추가
            if (trustAssessment != null) {
                addAIAssessment(builder, trustAssessment);
            }

            // 결정 이유 추출
            String reason = extractDecisionReason(decision, trustAssessment);
            builder.reason(reason);

            // AI Native v3.1: HCADContext 세션 컨텍스트 필드 설정
            // LLM 프롬프트에서 NOT_PROVIDED 방지
            builder.isNewSession(requestInfo.getIsNewSession())
                    .isNewDevice(requestInfo.getIsNewDevice())
                    .recentRequestCount(requestInfo.getRecentRequestCount());

            // 메타데이터 추가 (RequestInfo 사용)
            Map<String, Object> metadata = extractWebMetadata(requestInfo, authentication);
            builder.metadata(metadata);

            // 이벤트 발행
            AuthorizationDecisionEvent event = builder.build();
            eventPublisher.publishEvent(event);

            log.debug("Web authorization event published: eventId={}, resource={}, result={}",
                    event.getEventId(), event.getResource(), event.getResult());

        } catch (Exception e) {
            log.error("Failed to publish web authorization event", e);
        }
    }
    
    /**
     * @Protectable 메서드에 대한 인가 결정 이벤트 발행 (동기 진입점)
     * AuthorizationManagerMethodInterceptor에서 호출
     *
     * 동기 컨텍스트에서 RequestInfo를 먼저 추출한 후 비동기 처리.
     * Tomcat request 객체 재활용(recycle) 문제 방지.
     */
    public void publishMethodAuthorizationDecisionAsync(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {

        // 동기 컨텍스트에서 RequestInfo 추출 (가능한 경우)
        RequestInfo requestInfo = null;
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest request = attrs.getRequest();
            requestInfo = RequestInfo.from(request);
            // 이벤트 발행 플래그 설정 (동기 컨텍스트에서 수행)
            request.setAttribute("security.event.published", true);
        }

        // 추출된 정보로 비동기 처리
        publishMethodAuthorizationDecisionAsyncInternal(
                methodInvocation, authentication, granted, denialReason, requestInfo);
    }

    /**
     * @Protectable 메서드 인가 이벤트 발행 (내부 비동기 처리)
     *
     * RequestInfo를 사용하여 비동기 스레드에서 안전하게 처리.
     */
    @Async("securityEventExecutor")
    void publishMethodAuthorizationDecisionAsyncInternal(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason,
            RequestInfo requestInfo) {

        try {
            String resource = methodInvocation.getMethod().getDeclaringClass().getSimpleName() +
                    "." + methodInvocation.getMethod().getName();

            AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder =
                    AuthorizationDecisionEvent.builder();

            // 기본 정보 설정
            String userName = authentication != null ? authentication.getName() : null;
            builder.eventId(UUID.randomUUID().toString())
                    .timestamp(Instant.now())
                    .eventType("PROTECTABLE_METHOD")
                    .principal(userName != null ? userName : "anonymous")
                    .userId(userName)
                    .resource(resource)
                    .action("EXECUTE")
                    .result(granted ?
                            AuthorizationDecisionEvent.AuthorizationResult.ALLOWED :
                            AuthorizationDecisionEvent.AuthorizationResult.DENIED)
                    .reason(denialReason);

            // 사용자 정보 (조직 ID 및 추가 정보)
            if (authentication != null) {
                builder.organizationId(extractOrganizationId(authentication));

                // Trust Score 추출
                if (authentication.getDetails() instanceof TrustAssessment) {
                    TrustAssessment assessment = (TrustAssessment) authentication.getDetails();
                    builder.trustScore(assessment.score());
                    addAIAssessment(builder, assessment);
                } else {
                    // Zero Trust v6.0: TrustAssessment 없을 때 기본 trustScore 설정
                    // 기본값 0.7 = 1.0 - threatScore(0.3) (ZeroTrustSecurityService 기본값)
                    // 이전 문제: trustScore 미설정 → LLM이 신뢰도 판단 불가
                    builder.trustScore(0.7);
                }
            } else {
                // Zero Trust v6.0: 인증 정보 없으면 낮은 trustScore 설정
                // 인증되지 않은 요청은 신뢰도가 낮음
                builder.trustScore(0.5);
            }

            // HTTP 요청 정보 추가 (RequestInfo 사용, null 가능)
            if (requestInfo != null) {
                builder.clientIp(requestInfo.getClientIp())
                        .sessionId(requestInfo.getSessionId())
                        .userAgent(requestInfo.getUserAgent())
                        .httpMethod(requestInfo.getMethod());

                // AI Native v3.1: HCADContext 세션 컨텍스트 필드 설정
                // LLM 프롬프트에서 NOT_PROVIDED 방지
                builder.isNewSession(requestInfo.getIsNewSession())
                        .isNewDevice(requestInfo.getIsNewDevice())
                        .recentRequestCount(requestInfo.getRecentRequestCount());
            }

            // 메타데이터 추가
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("methodClass", methodInvocation.getMethod().getDeclaringClass().getName());
            metadata.put("methodName", methodInvocation.getMethod().getName());
            metadata.put("parameterTypes", methodInvocation.getMethod().getParameterTypes());
            builder.metadata(metadata);

            // 이벤트 발행
            AuthorizationDecisionEvent event = builder.build();
            eventPublisher.publishEvent(event);

            log.debug("Method authorization event published: eventId={}, resource={}, granted={}",
                    event.getEventId(), resource, granted);

        } catch (Exception e) {
            log.error("Failed to publish method authorization event", e);
        }
    }
    
    /**
     * 감사 이벤트 발행
     */
    @Async("securityEventExecutor")
    public void publishAuditEvent(
            String principal,
            String resource,
            String action,
            String result,
            String clientIp,
            String sessionId,
            Map<String, Object> details) {
        
        try {
            AuditEvent auditEvent = AuditEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .auditType("AUTHORIZATION_AUDIT")
                .principal(principal)
                .resource(resource)
                .action(action)
                .result(result)
                .clientIp(clientIp)
                .sessionId(sessionId)
                .details(details)
                .build();
            
            eventPublisher.publishEvent(auditEvent);
            
            log.trace("Audit event published: eventId={}, principal={}, action={}", 
                auditEvent.getEventId(), principal, action);
                
        } catch (Exception e) {
            log.error("Failed to publish audit event", e);
        }
    }
    
    /**
     * 클라이언트 IP 추출 (X-Forwarded-For 헤더 고려)
     */
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * User-Agent 추출 (테스트용 X-Simulated-User-Agent 헤더 우선)
     *
     * 브라우저 보안 정책으로 User-Agent 헤더를 직접 수정할 수 없어서
     * 테스트 환경에서는 X-Simulated-User-Agent 커스텀 헤더를 사용합니다.
     *
     * @param request HTTP 요청
     * @return User-Agent 문자열 (curl, python-requests 등 봇 구별에 사용)
     */
    private String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("X-Simulated-User-Agent");
        if (userAgent != null && !userAgent.isEmpty()) {
            return userAgent;
        }
        userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    /**
     * 요청 ID 추출
     */
    private String extractRequestId(HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-ID");
        if (requestId == null || requestId.isEmpty()) {
            requestId = UUID.randomUUID().toString();
        }
        return requestId;
    }
    
    /**
     * 조직 ID 추출
     */
    private String extractOrganizationId(Authentication authentication) {
        // 실제 구현은 프로젝트의 인증 구조에 따라 다를 수 있음
        // 기본값 반환
        return "default-org";
    }
    
    /**
     * RequestContext에서 HTTP 정보 추출
     */
    private void extractHttpInfoFromContext(AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder) {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest request = attrs.getRequest();
            builder.clientIp(extractClientIp(request))
                   .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                   .userAgent(extractUserAgent(request))  // X-Simulated-User-Agent 우선 읽기
                   .httpMethod(request.getMethod());
        }
    }
    
    /**
     * AI Assessment 정보 추가
     */
    private void addAIAssessment(AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder, 
                                  TrustAssessment trustAssessment) {
        AuthorizationDecisionEvent.AIAssessment aiAssessment = 
            AuthorizationDecisionEvent.AIAssessment.builder()
                .trustScore(trustAssessment.score())
                .riskTags(trustAssessment.riskTags() != null ?
                    trustAssessment.riskTags().toArray(new String[0]) : null)
                .anomalyDetected(detectAnomaly(trustAssessment))
                .behaviorPattern(extractBehaviorPattern(trustAssessment))
                .recommendation(trustAssessment.summary())
                .confidence(trustAssessment.score())
                .build();
        
        builder.aiAssessment(aiAssessment);
        builder.trustScore(trustAssessment.score());
        builder.riskScore(calculateRiskScore(trustAssessment));
    }
    
    /**
     * 웹 요청 메타데이터 추출 (RequestInfo 사용)
     */
    private Map<String, Object> extractWebMetadata(RequestInfo requestInfo, Authentication authentication) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestPath", requestInfo.getServletPath());
        metadata.put("queryString", requestInfo.getQueryString());
        metadata.put("remoteHost", requestInfo.getRemoteHost());
        metadata.put("protocol", requestInfo.getProtocol());
        metadata.put("secure", requestInfo.isSecure());

        if (authentication != null) {
            metadata.put("authorities", authentication.getAuthorities().toString());
            metadata.put("authenticated", authentication.isAuthenticated());
        }

        return metadata;
    }
    
    /**
     * 인가 결정 이유 추출
     */
    private String extractDecisionReason(AuthorizationDecision decision, TrustAssessment assessment) {
        if (assessment != null && assessment.summary() != null) {
            return assessment.summary();
        }
        
        return decision.isGranted() ? 
            "Access granted based on security policy" : 
            "Access denied based on security policy";
    }
    
    /**
     * 이상 탐지 여부 판단
     */
    private Boolean detectAnomaly(TrustAssessment assessment) {
        if (assessment.riskTags() == null || assessment.riskTags().isEmpty()) {
            return false;
        }
        
        List<String> anomalyTags = List.of(
            "NEW_IP", "NEW_DEVICE", "UNUSUAL_TIME", "UNUSUAL_LOCATION",
            "SUSPICIOUS_PATTERN", "BRUTE_FORCE", "CREDENTIAL_STUFFING"
        );
        
        return assessment.riskTags().stream()
            .anyMatch(tag -> anomalyTags.contains(tag.toUpperCase()));
    }
    
    /**
     * 행동 패턴 추출
     */
    private String extractBehaviorPattern(TrustAssessment assessment) {
        if (assessment.riskTags() == null || assessment.riskTags().isEmpty()) {
            return "Normal access pattern";
        }
        
        StringBuilder pattern = new StringBuilder();
        for (String tag : assessment.riskTags()) {
            if (pattern.length() > 0) {
                pattern.append(", ");
            }
            pattern.append(tagToPattern(tag));
        }
        
        return pattern.toString();
    }
    
    /**
     * 위험 태그를 행동 패턴 설명으로 변환
     */
    private String tagToPattern(String tag) {
        return switch (tag.toUpperCase()) {
            case "NEW_IP" -> "Access from new IP address";
            case "NEW_DEVICE" -> "Access from new device";
            case "OFF_HOURS" -> "Off-hours access";
            case "UNUSUAL_TIME" -> "Unusual time access";
            case "UNUSUAL_LOCATION" -> "Unusual location access";
            case "HIGH_PRIVILEGE" -> "High privilege operation";
            case "SENSITIVE_DATA" -> "Sensitive data access";
            case "BULK_ACCESS" -> "Bulk data access";
            case "RAPID_REQUESTS" -> "Rapid request pattern";
            default -> tag.toLowerCase().replace('_', ' ');
        };
    }
    
    /**
     * AI Native: riskScore 계산 제거
     *
     * 이전: return 1.0 - trustScore (하드코딩 공식)
     * 변경: trustScore만 제공, LLM이 직접 위험도 판단
     *
     * 이 메서드는 호환성을 위해 유지하되 null 반환
     * (프롬프트 템플릿에서 riskScore 참조 제거됨)
     */
    private Double calculateRiskScore(TrustAssessment assessment) {
        // AI Native: 하드코딩 공식 제거 - LLM이 trustScore로 직접 판단
        return null;
    }

    /**
     * HTTP 요청 정보를 담는 불변 DTO
     * 비동기 처리 시 HttpServletRequest 객체 재활용(recycle) 문제 방지
     *
     * Tomcat은 HTTP 요청 처리 완료 후 request 객체를 재활용하므로,
     * @Async 비동기 메서드에서 직접 접근하면 IllegalStateException 발생
     */
    @Builder
    @Getter
    public static class RequestInfo {
        private final String requestUri;
        private final String method;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String requestId;
        private final String servletPath;
        private final String queryString;
        private final String remoteHost;
        private final String protocol;
        private final boolean secure;

        // AI Native v3.1: HCADContext 세션 컨텍스트 필드
        // HCADFilter에서 설정한 request attribute 값
        private final Boolean isNewSession;
        private final Boolean isNewDevice;
        private final Integer recentRequestCount;

        /**
         * HttpServletRequest에서 RequestInfo 추출 (동기 컨텍스트에서 호출 필수)
         *
         * AI Native v3.1: HCADContext 필드 추출 추가
         * - hcad.is_new_session: 새 세션 여부
         * - hcad.is_new_device: 새 디바이스 여부
         * - hcad.recent_request_count: 최근 요청 수
         */
        public static RequestInfo from(HttpServletRequest request) {
            return RequestInfo.builder()
                    .requestUri(request.getRequestURI())
                    .method(request.getMethod())
                    .clientIp(extractClientIpStatic(request))
                    .userAgent(extractUserAgentStatic(request))
                    .sessionId(request.getSession(false) != null ?
                            request.getSession(false).getId() : null)
                    .requestId(extractRequestIdStatic(request))
                    .servletPath(request.getServletPath())
                    .queryString(request.getQueryString())
                    .remoteHost(request.getRemoteHost())
                    .protocol(request.getProtocol())
                    .secure(request.isSecure())
                    // AI Native v3.1: HCADContext 필드 추출 (HCADFilter에서 설정)
                    .isNewSession((Boolean) request.getAttribute("hcad.is_new_session"))
                    .isNewDevice((Boolean) request.getAttribute("hcad.is_new_device"))
                    .recentRequestCount((Integer) request.getAttribute("hcad.recent_request_count"))
                    .build();
        }

        private static String extractClientIpStatic(HttpServletRequest request) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }
            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                return xRealIp;
            }
            return request.getRemoteAddr();
        }

        private static String extractUserAgentStatic(HttpServletRequest request) {
            String userAgent = request.getHeader("X-Simulated-User-Agent");
            if (userAgent != null && !userAgent.isEmpty()) {
                return userAgent;
            }
            userAgent = request.getHeader("User-Agent");
            return userAgent != null ? userAgent : "unknown";
        }

        private static String extractRequestIdStatic(HttpServletRequest request) {
            String requestId = request.getHeader("X-Request-ID");
            return (requestId != null && !requestId.isEmpty()) ?
                    requestId : UUID.randomUUID().toString();
        }
    }
}