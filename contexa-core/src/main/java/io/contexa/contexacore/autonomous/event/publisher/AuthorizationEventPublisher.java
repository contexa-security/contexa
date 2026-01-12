package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 통합 인가 이벤트 발행자
 *
 * AI Native 비동기 구조 최적화 (Phase 2):
 * - Spring Event 제거 -> Kafka 직접 전송
 * - @Async 제거 -> kafkaTemplate.send()가 이미 비동기
 * - Phase 14 Redis 락 체크 통합 (중복 LLM 분석 방지)
 *
 * 인가 결정 이벤트를 Kafka로 직접 발행합니다.
 * - CustomDynamicAuthorizationManager: 웹 요청 인가
 * - AuthorizationManagerMethodInterceptor: @Protectable 메서드 인가
 */
@Slf4j
public class AuthorizationEventPublisher {

    private final KafkaSecurityEventPublisher kafkaPublisher;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Phase 14: 분석 락 TTL (30초)
     * 동시 @Protectable 접근 시 중복 LLM 분석 방지
     */
    private static final Duration ANALYSIS_LOCK_TTL = Duration.ofSeconds(30);

    // AuditEvent 발행용 (기존 호환성 유지)
    private final ApplicationEventPublisher eventPublisher;

    /**
     * 생성자 (AI Native 비동기 구조 최적화)
     *
     * @param kafkaPublisher Kafka 이벤트 발행자
     * @param tieredStrategyProperties Tiered 전략 설정
     * @param redisTemplate Redis 템플릿 (Phase 14 락용)
     * @param eventPublisher Spring Event 발행자 (AuditEvent용, 레거시 호환)
     */
    public AuthorizationEventPublisher(
            KafkaSecurityEventPublisher kafkaPublisher,
            TieredStrategyProperties tieredStrategyProperties,
            RedisTemplate<String, Object> redisTemplate,
            ApplicationEventPublisher eventPublisher) {
        this.kafkaPublisher = kafkaPublisher;
        this.tieredStrategyProperties = tieredStrategyProperties;
        this.redisTemplate = redisTemplate;
        this.eventPublisher = eventPublisher;
    }

    /**
     * 웹 요청에 대한 인가 결정 이벤트 발행
     *
     * AI Native 비동기 구조 최적화 (Phase 2):
     * - @Async 제거: kafkaTemplate.send()가 이미 비동기 (fire-and-forget)
     * - Spring Event 제거: Kafka 직접 전송
     * - Phase 14 Redis 락 체크 통합: 중복 LLM 분석 방지
     *
     * 동기 컨텍스트에서 request 정보 추출 후 Kafka로 직접 전송.
     * 사용자에게 즉시 응답 반환 (Zero Trust 핵심 원칙)
     */
    public void publishWebAuthorizationDecision(
            Authentication authentication,
            HttpServletRequest request,
            AuthorizationDecision decision,
            TrustAssessment trustAssessment) {

        long startTime = System.currentTimeMillis();

        try {
            // 1. 동기: RequestInfo 추출 (Tomcat request 재활용 방지)
            RequestInfo requestInfo = RequestInfo.from(request, tieredStrategyProperties.getSecurity());

            // 2. 이벤트 발행 플래그 설정 (중복 발행 방지)
            request.setAttribute("security.event.published", true);

            // 3. Phase 14: Redis 락 체크 (중복 LLM 분석 방지)
            String userId = authentication != null ? authentication.getName() : null;
            if (!shouldPublishForAnalysis(userId)) {
                log.debug("[AuthorizationEventPublisher] Phase 14: LLM 분석 스킵 (이미 분석 중/유효한 결과 존재) - userId: {}, resource: {}",
                        userId, requestInfo.getRequestUri());
                return;
            }

            // 4. 동기: AuthorizationDecisionEvent 생성
            AuthorizationDecisionEvent event = buildAuthorizationEvent(
                    authentication, requestInfo, decision, trustAssessment, "WEB_REQUEST");

            // 5. 비동기: Kafka 직접 전송 (fire-and-forget)
            kafkaPublisher.publishAuthorizationEvent(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[AuthorizationEventPublisher] Web authorization event queued - eventId: {}, resource: {}, result: {}, duration: {}ms",
                    event.getEventId(), event.getResource(), event.getResult(), duration);

            // 성능 경고 (10ms 초과 시)
            if (duration > 10) {
                log.warn("[AuthorizationEventPublisher] Event processing exceeded 10ms threshold: {}ms for resource: {}",
                        duration, requestInfo.getRequestUri());
            }

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[AuthorizationEventPublisher] Failed to publish web authorization event - duration: {}ms", duration, e);
            // 인가 결정 자체는 성공했으므로 예외를 전파하지 않음
        }
    }

    /**
     * Phase 14: LLM 분석 발행 여부 결정
     *
     * Redis SETNX 패턴으로 중복 LLM 분석 방지:
     * - 유효한 분석 결과 존재 시: false (발행 스킵)
     * - 분석 락 획득 실패 시: false (이미 다른 요청이 분석 중)
     * - 분석 락 획득 성공 시: true (발행 진행)
     *
     * @param userId 사용자 ID (null이면 항상 true)
     * @return 발행 여부
     */
    private boolean shouldPublishForAnalysis(String userId) {
        if (userId == null || userId.isEmpty() || "anonymous".equals(userId)) {
            return true;  // 익명 사용자는 항상 분석
        }

        try {
            // 캐시된 유효한 분석 결과 확인
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object existingAction = redisTemplate.opsForHash().get(analysisKey, "action");
            if (existingAction != null && !"PENDING_ANALYSIS".equals(existingAction.toString())) {
                // 이미 유효한 분석 결과 있음 - 재분석 불필요
                log.debug("[AuthorizationEventPublisher] Phase 14: 유효한 분석 결과 존재 - userId: {}, action: {}",
                        userId, existingAction);
                return false;
            }

            // SETNX로 분석 락 획득 시도
            String lockKey = ZeroTrustRedisKeys.analysisLock(userId);
            Boolean acquired = redisTemplate.opsForValue()
                    .setIfAbsent(lockKey, "1", ANALYSIS_LOCK_TTL);

            if (Boolean.TRUE.equals(acquired)) {
                log.debug("[AuthorizationEventPublisher] Phase 14: 분석 락 획득 성공 - userId: {}", userId);
                return true;
            } else {
                log.debug("[AuthorizationEventPublisher] Phase 14: 분석 락 획득 실패 (이미 분석 중) - userId: {}", userId);
                return false;
            }

        } catch (Exception e) {
            log.warn("[AuthorizationEventPublisher] Phase 14: 분석 락 확인 실패 - userId: {}, 분석 진행", userId, e);
            // Redis 오류 시 안전하게 분석 진행 (fail-open)
            return true;
        }
    }

    /**
     * AuthorizationDecisionEvent 빌드
     */
    private AuthorizationDecisionEvent buildAuthorizationEvent(
            Authentication authentication,
            RequestInfo requestInfo,
            AuthorizationDecision decision,
            TrustAssessment trustAssessment,
            String eventType) {

        AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder =
                AuthorizationDecisionEvent.builder();

        // 기본 정보 설정
        String userName = authentication != null ? authentication.getName() : null;
        builder.eventId(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .eventType(eventType)
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
        builder.isNewSession(requestInfo.getIsNewSession())
                .isNewUser(requestInfo.getIsNewUser())
                .isNewDevice(requestInfo.getIsNewDevice())
                .recentRequestCount(requestInfo.getRecentRequestCount());

        // 메타데이터 추가
        Map<String, Object> metadata = extractWebMetadata(requestInfo, authentication);
        builder.metadata(metadata);

        return builder.build();
    }
    
    /**
     * @Protectable 메서드에 대한 인가 결정 이벤트 발행
     * AuthorizationManagerMethodInterceptor에서 호출
     *
     * AI Native 비동기 구조 최적화 (Phase 2):
     * - @Async 제거: kafkaTemplate.send()가 이미 비동기
     * - Spring Event 제거: Kafka 직접 전송
     * - Phase 14 Redis 락 체크 통합
     */
    public void publishMethodAuthorizationDecisionAsync(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {

        long startTime = System.currentTimeMillis();

        try {
            // 1. 동기: RequestInfo 추출 (가능한 경우)
            RequestInfo requestInfo = null;
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                requestInfo = RequestInfo.from(request, tieredStrategyProperties.getSecurity());
                request.setAttribute("security.event.published", true);
            }

            // 2. Phase 14: Redis 락 체크 (중복 LLM 분석 방지)
            String userId = authentication != null ? authentication.getName() : null;
            if (!shouldPublishForAnalysis(userId)) {
                String resource = methodInvocation.getMethod().getDeclaringClass().getSimpleName() +
                        "." + methodInvocation.getMethod().getName();
                log.debug("[AuthorizationEventPublisher] Phase 14: LLM 분석 스킵 (이미 분석 중/유효한 결과 존재) - userId: {}, resource: {}",
                        userId, resource);
                return;
            }

            // 3. 동기: AuthorizationDecisionEvent 생성
            AuthorizationDecisionEvent event = buildMethodAuthorizationEvent(
                    methodInvocation, authentication, granted, denialReason, requestInfo);

            // 4. 비동기: Kafka 직접 전송 (fire-and-forget)
            kafkaPublisher.publishAuthorizationEvent(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[AuthorizationEventPublisher] Method authorization event queued - eventId: {}, resource: {}, granted: {}, duration: {}ms",
                    event.getEventId(), event.getResource(), granted, duration);

            // 성능 경고 (10ms 초과 시)
            if (duration > 10) {
                log.warn("[AuthorizationEventPublisher] Event processing exceeded 10ms threshold: {}ms for method: {}",
                        duration, event.getResource());
            }

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[AuthorizationEventPublisher] Failed to publish method authorization event - duration: {}ms", duration, e);
        }
    }

    /**
     * Method AuthorizationDecisionEvent 빌드
     */
    private AuthorizationDecisionEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason,
            RequestInfo requestInfo) {

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
                builder.trustScore(0.7);
            }
        } else {
            builder.trustScore(0.5);
        }

        // HTTP 요청 정보 추가 (RequestInfo 사용, null 가능)
        if (requestInfo != null) {
            builder.clientIp(requestInfo.getClientIp())
                    .sessionId(requestInfo.getSessionId())
                    .userAgent(requestInfo.getUserAgent())
                    .httpMethod(requestInfo.getMethod());

            // AI Native v3.1: HCADContext 세션 컨텍스트 필드 설정
            builder.isNewSession(requestInfo.getIsNewSession())
                    .isNewUser(requestInfo.getIsNewUser())
                    .isNewDevice(requestInfo.getIsNewDevice())
                    .recentRequestCount(requestInfo.getRecentRequestCount());
        }

        // 메타데이터 추가
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("methodClass", methodInvocation.getMethod().getDeclaringClass().getName());
        metadata.put("methodName", methodInvocation.getMethod().getName());
        metadata.put("parameterTypes", methodInvocation.getMethod().getParameterTypes());
        builder.metadata(metadata);

        return builder.build();
    }
    
    /**
     * 감사 이벤트 발행
     *
     * AI Native 비동기 구조 최적화 (Phase 2):
     * - @Async 제거 (감사 이벤트는 동기로 처리해도 무방)
     * - Spring Event는 유지 (감사 로그 시스템과의 호환성)
     */
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
        private final Boolean isNewUser;
        private final Boolean isNewDevice;
        private final Integer recentRequestCount;

        /**
         * HttpServletRequest에서 RequestInfo 추출 (동기 컨텍스트에서 호출 필수)
         *
         * AI Native v3.1: HCADContext 필드 추출 추가
         * D1: Security 설정 기반 신뢰 프록시 검증 추가
         *
         * @param request HTTP 요청
         * @param security Security 설정 (신뢰 프록시 목록 포함)
         * @return RequestInfo 불변 DTO
         */
        public static RequestInfo from(HttpServletRequest request, TieredStrategyProperties.Security security) {
            return RequestInfo.builder()
                    .requestUri(request.getRequestURI())
                    .method(request.getMethod())
                    .clientIp(extractClientIpStatic(request, security))
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
                    .isNewUser((Boolean) request.getAttribute("hcad.is_new_user"))
                    .isNewDevice((Boolean) request.getAttribute("hcad.is_new_device"))
                    .recentRequestCount((Integer) request.getAttribute("hcad.recent_request_count"))
                    .build();
        }

        /**
         * D1: Zero Trust IP 주소 검증
         *
         * X-Forwarded-For 스푸핑 방지를 위해 신뢰 프록시 기반 검증 수행.
         * request.getRemoteAddr()가 신뢰 프록시 목록에 있을 때만 X-Forwarded-For 사용.
         *
         * @param request HTTP 요청
         * @param security Security 설정 (null이면 기본 동작: X-Forwarded-For 무조건 신뢰)
         * @return 검증된 클라이언트 IP
         */
        private static String extractClientIpStatic(HttpServletRequest request, TieredStrategyProperties.Security security) {
            String remoteAddr = request.getRemoteAddr();

            // Security 설정이 없거나 검증 비활성화면 기존 동작 유지 (개발 환경용)
            if (security == null || !security.isTrustedProxyValidationEnabled()) {
                return extractClientIpLegacy(request);
            }

            List<String> trustedProxies = security.getTrustedProxies();

            // 신뢰 프록시 목록이 비어있으면 X-Forwarded-For 사용 안 함 (가장 안전)
            if (trustedProxies == null || trustedProxies.isEmpty()) {
                log.debug("[D1][Zero Trust] No trusted proxies configured, using remoteAddr: {}", remoteAddr);
                return remoteAddr;
            }

            // remoteAddr이 신뢰 프록시 목록에 있는지 확인
            if (isTrustedProxy(remoteAddr, trustedProxies)) {
                // 신뢰 프록시에서 온 요청 → X-Forwarded-For 사용
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    String clientIp = xForwardedFor.split(",")[0].trim();
                    log.debug("[D1][Zero Trust] Trusted proxy {}, using X-Forwarded-For: {}", remoteAddr, clientIp);
                    return clientIp;
                }

                String xRealIp = request.getHeader("X-Real-IP");
                if (xRealIp != null && !xRealIp.isEmpty()) {
                    log.debug("[D1][Zero Trust] Trusted proxy {}, using X-Real-IP: {}", remoteAddr, xRealIp);
                    return xRealIp;
                }
            } else {
                // 신뢰 프록시가 아닌 곳에서 온 요청 → remoteAddr 사용
                // X-Forwarded-For가 있어도 무시 (스푸핑 방지)
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    log.warn("[D1][Zero Trust] Untrusted source {} sent X-Forwarded-For header (ignored): {}",
                            remoteAddr, xForwardedFor);
                }
            }

            return remoteAddr;
        }

        /**
         * 기존 IP 추출 로직 (레거시, 개발 환경용)
         */
        private static String extractClientIpLegacy(HttpServletRequest request) {
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
         * IP가 신뢰 프록시 목록에 있는지 확인
         *
         * CIDR 표기법 지원 (예: "10.0.0.0/8", "192.168.0.0/16")
         *
         * @param ip 확인할 IP 주소
         * @param trustedProxies 신뢰 프록시 목록 (IP 또는 CIDR)
         * @return 신뢰 프록시면 true
         */
        private static boolean isTrustedProxy(String ip, List<String> trustedProxies) {
            if (ip == null || trustedProxies == null) {
                return false;
            }

            for (String trusted : trustedProxies) {
                if (trusted == null || trusted.isEmpty()) {
                    continue;
                }

                try {
                    if (trusted.contains("/")) {
                        // CIDR 표기법 (예: "10.0.0.0/8")
                        if (isIpInCidr(ip, trusted)) {
                            return true;
                        }
                    } else {
                        // 단일 IP (정확히 일치)
                        if (trusted.equals(ip)) {
                            return true;
                        }
                    }
                } catch (Exception e) {
                    log.warn("[D1] Invalid trusted proxy format: {}", trusted, e);
                }
            }

            return false;
        }

        /**
         * IP가 CIDR 범위 내에 있는지 확인
         *
         * @param ip IP 주소
         * @param cidr CIDR 표기법 (예: "10.0.0.0/8")
         * @return CIDR 범위 내면 true
         */
        private static boolean isIpInCidr(String ip, String cidr) {
            try {
                String[] parts = cidr.split("/");
                if (parts.length != 2) {
                    return false;
                }

                String networkAddress = parts[0];
                int prefixLength = Integer.parseInt(parts[1]);

                InetAddress inetIp = InetAddress.getByName(ip);
                InetAddress inetNetwork = InetAddress.getByName(networkAddress);

                byte[] ipBytes = inetIp.getAddress();
                byte[] networkBytes = inetNetwork.getAddress();

                // IPv4와 IPv6 호환성 확인
                if (ipBytes.length != networkBytes.length) {
                    return false;
                }

                // 네트워크 마스크 생성 및 비교
                int fullBytes = prefixLength / 8;
                int remainingBits = prefixLength % 8;

                // 전체 바이트 비교
                for (int i = 0; i < fullBytes; i++) {
                    if (ipBytes[i] != networkBytes[i]) {
                        return false;
                    }
                }

                // 남은 비트 비교
                if (remainingBits > 0 && fullBytes < ipBytes.length) {
                    int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                    if ((ipBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) {
                        return false;
                    }
                }

                return true;
            } catch (Exception e) {
                log.debug("[D1] CIDR check failed for ip={}, cidr={}: {}", ip, cidr, e.getMessage());
                return false;
            }
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