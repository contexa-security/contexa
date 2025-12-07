package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacommon.domain.TrustAssessment;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
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
     * 웹 요청에 대한 인가 결정 이벤트 발행 (비동기)
     * CustomDynamicAuthorizationManager에서 호출
     * 
     * 일반적인 경우 비동기로 처리하여 성능 영향 최소화
     */
    @Async("securityEventExecutor")
    public void publishWebAuthorizationDecisionAsync(
            Authentication authentication,
            HttpServletRequest request,
            AuthorizationDecision decision,
            TrustAssessment trustAssessment) {
        
        try {
            AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder = 
                AuthorizationDecisionEvent.builder();
            
            // 기본 정보 설정
            builder.eventId(UUID.randomUUID().toString())
                   .timestamp(Instant.now())
                   .eventType("WEB_REQUEST")
                   .principal(authentication != null ? authentication.getName() : "anonymous")
                   .resource(request.getRequestURI())
                   .action(request.getMethod())
                   .httpMethod(request.getMethod())
                   .result(decision.isGranted() ?
                       AuthorizationDecisionEvent.AuthorizationResult.ALLOWED :
                       AuthorizationDecisionEvent.AuthorizationResult.DENIED)
                   .clientIp(extractClientIp(request))
                   .userAgent(extractUserAgent(request))  // X-Simulated-User-Agent 우선 읽기
                   .sessionId(request.getSession(false) != null ? 
                       request.getSession(false).getId() : null)
                   .requestId(extractRequestId(request));
            
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
            
            // 메타데이터 추가
            Map<String, Object> metadata = extractWebMetadata(request, authentication);
            builder.metadata(metadata);
            
            // 이벤트 발행
            AuthorizationDecisionEvent event = builder.build();
            eventPublisher.publishEvent(event);

            // 이벤트 발행 플래그 설정 (SecurityEventPublishingFilter에서 중복 방지)
            request.setAttribute("security.event.published", true);

            log.debug("Web authorization event published: eventId={}, resource={}, result={}",
                event.getEventId(), event.getResource(), event.getResult());

        } catch (Exception e) {
            log.error("Failed to publish web authorization event", e);
        }
    }
    
    /**
     * 웹 요청에 대한 인가 결정 이벤트 발행 (동기)
     * 
     * 중요한 보안 이벤트의 경우 동기로 처리하여 확실히 기록
     */
    public void publishWebAuthorizationDecision(
            Authentication authentication,
            HttpServletRequest request,
            AuthorizationDecision decision,
            TrustAssessment trustAssessment) {
        
        publishWebAuthorizationDecisionAsync(authentication, request, decision, trustAssessment);
    }
    
    /**
     * @Protectable 메서드에 대한 인가 결정 이벤트 발행 (비동기)
     * AuthorizationManagerMethodInterceptor에서 호출
     */
    @Async("securityEventExecutor")
    public void publishMethodAuthorizationDecisionAsync(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        
        try {
            String resource = methodInvocation.getMethod().getDeclaringClass().getSimpleName() + 
                            "." + methodInvocation.getMethod().getName();
            
            AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder = 
                AuthorizationDecisionEvent.builder();
            
            // 기본 정보 설정
            builder.eventId(UUID.randomUUID().toString())
                   .timestamp(Instant.now())
                   .eventType("PROTECTABLE_METHOD")
                   .principal(authentication != null ? authentication.getName() : "anonymous")
                   .resource(resource)
                   .action("EXECUTE")
                   .result(granted ? 
                       AuthorizationDecisionEvent.AuthorizationResult.ALLOWED : 
                       AuthorizationDecisionEvent.AuthorizationResult.DENIED)
                   .reason(denialReason);
            
            // 사용자 정보
            if (authentication != null) {
                builder.userId(authentication.getName());
                builder.organizationId(extractOrganizationId(authentication));
                
                // Trust Score 추출
                if (authentication.getDetails() instanceof TrustAssessment) {
                    TrustAssessment assessment = (TrustAssessment) authentication.getDetails();
                    builder.trustScore(assessment.score());
                    addAIAssessment(builder, assessment);
                }
            }
            
            // HTTP 요청 정보 추출 (가능한 경우)
            extractHttpInfoFromContext(builder);
            
            // 메타데이터 추가
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("methodClass", methodInvocation.getMethod().getDeclaringClass().getName());
            metadata.put("methodName", methodInvocation.getMethod().getName());
            metadata.put("parameterTypes", methodInvocation.getMethod().getParameterTypes());
            builder.metadata(metadata);
            
            // 이벤트 발행
            AuthorizationDecisionEvent event = builder.build();
            eventPublisher.publishEvent(event);

            // 이벤트 발행 플래그 설정 (SecurityEventPublishingFilter에서 중복 방지)
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest httpRequest = attrs.getRequest();
                httpRequest.setAttribute("security.event.published", true);
            }

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
     * 웹 요청 메타데이터 추출
     */
    private Map<String, Object> extractWebMetadata(HttpServletRequest request, Authentication authentication) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestPath", request.getServletPath());
        metadata.put("queryString", request.getQueryString());
        metadata.put("remoteHost", request.getRemoteHost());
        metadata.put("protocol", request.getProtocol());
        metadata.put("secure", request.isSecure());
        
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
     * 위험 점수 계산
     */
    private Double calculateRiskScore(TrustAssessment assessment) {
        double trustScore = assessment.score();
        return 1.0 - trustScore;
    }
}