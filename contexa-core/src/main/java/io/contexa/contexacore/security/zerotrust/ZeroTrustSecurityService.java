package io.contexa.contexacore.security.zerotrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Zero Trust Security Service
 *
 * Spring Security의 세션 관리와 독립적으로 작동하는 Zero Trust 보안 서비스입니다.
 * Redis를 사용하여 위협 점수, 사용자 컨텍스트, 보안 메트릭을 관리합니다.
 *
 * 주요 기능:
 * - Threat Score 관리 및 시간 감쇠
 * - User Security Context 추적
 * - 동적 권한 조정
 * - 이상 행동 감지
 * - 세션 무효화 추적
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class ZeroTrustSecurityService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ThreatScoreOrchestrator threatScoreOrchestrator;
    private final RedisAtomicOperations redisAtomicOperations;
    private final ObjectMapper objectMapper;
    private final BaselineLearningService baselineLearningService;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${zerotrust.threat.initial:0.3}")
    private double initialThreatScore;

    @Value("${zerotrust.cache.ttl.hours:24}")
    private long cacheTtlHours;

    @Value("${zerotrust.session.tracking.enabled:true}")
    private boolean sessionTrackingEnabled;

    /**
     * SecurityContext에 Zero Trust 기능 적용 (인증된 사용자)
     *
     * @param context   SecurityContext
     * @param userId    사용자 ID
     * @param sessionId 세션 ID (옵션)
     * @param request
     */
    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!zeroTrustEnabled || context == null || userId == null) {
            return;
        }

        try {
            // AI Native v3.2.0: LLM이 action 직접 결정 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
            // - BLOCK: 극고위험군 (즉시 차단)
            // - CHALLENGE: 고위험군 (MFA 필요)
            String action = getLatestAction(userId);

            // 2. Threat Score 조회 (감사 로그/대시보드용)
            double threatScore = threatScoreOrchestrator.getThreatScore(userId);
            double trustScore = 1.0 - threatScore;

            // 3. User Context 조회 또는 생성
            UserSecurityContext userContext = getUserContext(userId);
            if (userContext == null) {
                userContext = createInitialUserContext(userId, sessionId);
            }

            // 4. 세션 추적 (옵션)
            if (sessionTrackingEnabled && sessionId != null) {
                trackUserSession(userId, sessionId);
            }

            // 5. AI Native: action 기반 동적 권한 조정
            adjustAuthoritiesByAction(context, action, userId, request);

            // 6. 컨텍스트 메타데이터 설정
            setZeroTrustMetadata(context, trustScore, threatScore, userContext, action);

            log.debug("[ZeroTrust][AI Native] Applied Zero Trust - User: {}, Action: {}, TrustScore: {:.3f}",
                userId, action, trustScore);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust to context for user: {}", userId, e);
        }
    }

    /**
     * 세션 무효화 처리
     *
     * @param sessionId 세션 ID
     * @param userId 사용자 ID
     * @param reason 무효화 사유
     */
    public void invalidateSession(String sessionId, String userId, String reason) {
        if (sessionId == null) {
            return;
        }

        try {
            String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);

            Map<String, Object> invalidationRecord = new HashMap<>();
            invalidationRecord.put("sessionId", sessionId);
            invalidationRecord.put("userId", userId);
            invalidationRecord.put("reason", reason);
            invalidationRecord.put("timestamp", System.currentTimeMillis());

            // Redis에 무효화 기록 저장
            redisTemplate.opsForValue().set(invalidKey, invalidationRecord,
                Duration.ofHours(cacheTtlHours));

            // 사용자 세션 추적에서 제거
            if (sessionTrackingEnabled && userId != null) {
                removeUserSession(userId, sessionId);
            }

            // AI Native: 세션 무효화 시 Threat Score 누적 제거
            // LLM이 다음 요청에서 세션 무효화 이력을 컨텍스트로 받아 직접 판단

            log.info("[ZeroTrust] Session invalidated - SessionId: {}, User: {}, Reason: {}",
                sessionId, userId, reason);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate session: {}", sessionId, e);
        }
    }

    /**
     * 세션이 무효화되었는지 확인
     *
     * @param sessionId 세션 ID
     * @return 무효화 여부
     */
    public boolean isSessionInvalidated(String sessionId) {
        if (sessionId == null) {
            return false;
        }

        try {
            String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);
            return Boolean.TRUE.equals(redisTemplate.hasKey(invalidKey));
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to check session invalidation: {}", sessionId, e);
            return false;
        }
    }

    /**
     * 사용자의 모든 세션 무효화
     *
     * @param userId 사용자 ID
     * @param reason 무효화 사유
     */
    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        try {
            Set<String> userSessions = getUserSessions(userId);

            for (String sessionId : userSessions) {
                invalidateSession(sessionId, userId, reason);
            }

            // 사용자 세션 추적 초기화
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.delete(sessionsKey);

            log.info("[ZeroTrust] All sessions invalidated for user: {} - Reason: {}",
                userId, reason);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate all sessions for user: {}", userId, e);
        }
    }

    /**
     * AI Native: Redis에서 LLM이 결정한 최신 action 조회
     *
     * 조회 우선순위:
     * 1. 차단 상태 확인 (RealtimeBlockStrategy가 저장)
     * 2. security:hcad:analysis:{userId} Hash에서 action 필드 조회
     * 3. 키 없음 -> PENDING_ANALYSIS (Zero Trust 기본값)
     *
     * Zero Trust 원칙:
     * - LLM 분석 전/실패/Redis 오류 시 기본값 "PENDING_ANALYSIS"
     * - "ALLOW" 기본값은 Zero Trust 원칙 위반 (신뢰하지 않고 항상 검증)
     *
     * AI Native v3.3.0:
     * - 4개 Action: ALLOW, BLOCK, CHALLENGE, ESCALATE
     * - INVESTIGATE, MONITOR 제거
     *
     * @param userId 사용자 ID
     * @return action 문자열 (ALLOW, BLOCK, CHALLENGE, ESCALATE, PENDING_ANALYSIS)
     */
    private String getLatestAction(String userId) {
        try {
            // 1. 차단 상태 확인 (RealtimeBlockStrategy가 저장)
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            Boolean isBlocked = (Boolean) redisTemplate.opsForValue().get(blockKey);
            if (Boolean.TRUE.equals(isBlocked)) {
                return "BLOCK";
            }

            // 2. security:hcad:analysis:{userId} Hash에서 action 필드 조회
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object action = redisTemplate.opsForHash().get(analysisKey, "action");
            if (action != null) {
                log.debug("[ZeroTrust] Action from hcadAnalysis: userId={}, action={}",
                        userId, action);
                return action.toString();
            }

            // 3. Zero Trust 기본값: PENDING_ANALYSIS (LLM 분석 전 상태)
            log.debug("[ZeroTrust] No action found, returning PENDING_ANALYSIS: userId={}", userId);
            return "PENDING_ANALYSIS";

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get action for user: {}", userId, e);
            // Zero Trust 원칙: 오류 시에도 PENDING_ANALYSIS (안전한 쪽으로)
            return "PENDING_ANALYSIS";
        }
    }

    /**
     * AI Native v3.3.0: action 기반 권한 동적 조정
     * <p>
     * Zero Trust 원칙에 따른 권한 조정 전략 (4개 Action):
     * - ALLOW: 기존 권한 유지 (LLM이 안전하다고 판단)
     * - BLOCK: 모든 권한 제거, ROLE_BLOCKED만 부여 (극고위험군)
     * - CHALLENGE: 기존 권한 제거, ROLE_MFA_REQUIRED (고위험군, MFA 완료 전 제한)
     * - ESCALATE: 기존 권한 제거, ROLE_REVIEW_REQUIRED (불확실, 검토 완료 전 제한)
     * - PENDING_ANALYSIS: 기존 권한 제거, ROLE_PENDING_ANALYSIS (분석 완료 전 제한)
     *
     * @param context SecurityContext
     * @param action  LLM이 결정한 action (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     * @param userId  사용자 ID
     * @param request
     */
    private void adjustAuthoritiesByAction(SecurityContext context, String action, String userId, HttpServletRequest request) {
        Authentication auth = context.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        Collection<? extends GrantedAuthority> currentAuthorities = auth.getAuthorities();
        // Zero Trust 원칙: 기존 권한을 복사하지 않고 새로 구성
        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>();

        switch (action) {
            case "ALLOW" -> {
                // 정상 - 원래 권한 복원 (LLM이 안전하다고 판단)
                // MFA 완료 등으로 CHALLENGE → ALLOW 전환 시 originalAuthorities 사용
                Object principal = auth.getPrincipal();
                if (principal instanceof UnifiedCustomUserDetails userDetails) {
                    // UnifiedCustomUserDetails에서 originalAuthorities 복원
                    adjustedAuthorities.addAll(userDetails.getOriginalAuthorities());
                    log.debug("[ZeroTrust][AI Native] Original authorities restored for user: {}", userId);
                } else {
                    // 폴백: 현재 권한 유지
                    adjustedAuthorities.addAll(currentAuthorities);
                }
            }
            case "BLOCK" -> {
                // 극고위험군 - 모든 권한 제거, 즉시 차단
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_BLOCKED"));
                log.warn("[ZeroTrust][AI Native] User BLOCKED (CRITICAL RISK): {}", userId);
            }
            case "CHALLENGE" -> {
                // 고위험군 - MFA 필요 (관리자/특권 권한 제거)
                // MFA 완료 후 원래 권한으로 복원됨 (다음 요청에서 action=ALLOW)
                resetActionOnMfaSuccess(userId, request);
                publishAuthenticationSuccessEvent(request, SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication());
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_MFA_REQUIRED"));
                log.info("[ZeroTrust][AI Native] MFA CHALLENGE required (HIGH RISK): {}", userId);
            }
            case "ESCALATE" -> {
                // 불확실 - 검토 필요 (관리자/특권 권한 제거)
                // 보안 담당자 승인 후 원래 권한으로 복원됨 (action=ALLOW로 변경)
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_REVIEW_REQUIRED"));
                log.warn("[ZeroTrust][AI Native] Security REVIEW required (ESCALATE): {}", userId);
            }
            case "PENDING_ANALYSIS" -> {
                // Zero Trust 핵심 원칙: 분석 미완료 상태 - 기본 권한만 유지
                // LLM 분석 전/실패/TTL 만료 시 적용
                // 분석 완료 후 원래 권한으로 복원됨 (action=ALLOW로 변경)
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_PENDING_ANALYSIS"));
                log.debug("[ZeroTrust][AI Native] PENDING_ANALYSIS - limited access: {}", userId);
            }
            default -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_LIMITED"));
                log.warn("[ZeroTrust][AI Native] Unknown action '{}', limited to ROLE_USER: {}", action, userId);
            }
        }

        if (!adjustedAuthorities.equals(new HashSet<>(currentAuthorities))) {
            double trustScore = 1.0 - threatScoreOrchestrator.getThreatScore(userId);
            double threatScore = threatScoreOrchestrator.getThreatScore(userId);

            Authentication adjustedAuth = new ZeroTrustAuthenticationToken(
                auth.getPrincipal(),
                auth.getCredentials(),
                adjustedAuthorities,
                trustScore,
                threatScore
            );
            context.setAuthentication(adjustedAuth);
        }
    }

    /**
     * SecurityContext에 Zero Trust 메타데이터 설정
     */
    private void setZeroTrustMetadata(SecurityContext context, double trustScore,
                                      double threatScore, UserSecurityContext userContext, String action) {
        if (context.getAuthentication() instanceof ZeroTrustAuthenticationToken zeroTrustAuth) {

            zeroTrustAuth.setTrustScore(trustScore);
            zeroTrustAuth.setThreatScore(threatScore);
            zeroTrustAuth.setUserContext(userContext);
            zeroTrustAuth.setLastEvaluated(LocalDateTime.now());

            // AI Native: action 정보 추가
            Map<String, Object> details = new HashMap<>();
            details.put("action", action);
            details.put("trustScore", trustScore);
            details.put("threatScore", threatScore);
            zeroTrustAuth.setDetails(details);
        }
    }

    /**
     * 사용자 보안 컨텍스트 조회
     */
    private UserSecurityContext getUserContext(String userId) {
        try {
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            Object stored = redisTemplate.opsForValue().get(contextKey);

            if (stored instanceof UserSecurityContext) {
                return (UserSecurityContext) stored;
            } else if (stored instanceof Map) {
                return objectMapper.convertValue(stored, UserSecurityContext.class);
            }

            return null;
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get user context for: {}", userId, e);
            return null;
        }
    }

    /**
     * 초기 사용자 보안 컨텍스트 생성
     */
    private UserSecurityContext createInitialUserContext(String userId, String sessionId) {
        UserSecurityContext context = UserSecurityContext.builder()
            .userId(userId)
            .currentThreatScore(initialThreatScore)
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .build();

        if (sessionId != null) {
            // SessionContext를 생성하여 추가
            UserSecurityContext.SessionContext sessionContext = UserSecurityContext.SessionContext.builder()
                .sessionId(sessionId)
                .startTime(LocalDateTime.now())
                .lastAccessTime(LocalDateTime.now())
                .active(true)
                .build();
            context.addSession(sessionContext);
        }

        // Redis에 저장
        try {
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            redisTemplate.opsForValue().set(contextKey, context,
                Duration.ofHours(cacheTtlHours));
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to save initial user context for: {}", userId, e);
        }

        return context;
    }

    /**
     * 사용자 세션 추적
     */
    private void trackUserSession(String userId, String sessionId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(sessionsKey, sessionId);
            redisTemplate.expire(sessionsKey, cacheTtlHours, TimeUnit.HOURS);

            String sessionUserKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.opsForValue().set(sessionUserKey, userId,
                Duration.ofHours(cacheTtlHours));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to track user session: {} -> {}", userId, sessionId, e);
        }
    }

    /**
     * 사용자 세션 제거
     */
    private void removeUserSession(String userId, String sessionId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().remove(sessionsKey, sessionId);

            String sessionUserKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.delete(sessionUserKey);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to remove user session: {} -> {}", userId, sessionId, e);
        }
    }

    /**
     * 사용자의 모든 활성 세션 조회
     */
    private Set<String> getUserSessions(String userId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            Set<Object> sessions = redisTemplate.opsForSet().members(sessionsKey);

            if (sessions != null) {
                return sessions.stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
            }

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get user sessions for: {}", userId, e);
        }

        return new HashSet<>();
    }

    /**
     * 현재 Threat Score 조회
     *
     * @param userId 사용자 ID
     * @return Threat Score
     */
    public double getThreatScore(String userId) {
        return threatScoreOrchestrator.getThreatScore(userId);
    }

    /**
     * Trust Tier 열거형
     */
    public enum TrustTier {
        FULL("Full Trust", 1.0),
        HIGH("High Trust", 0.8),
        MEDIUM("Medium Trust", 0.6),
        LOW("Low Trust", 0.4),
        UNTRUSTED("Untrusted", 0.0);

        private final String description;
        private final double weight;

        TrustTier(String description, double weight) {
            this.description = description;
            this.weight = weight;
        }

        public String getDescription() { return description; }
        public double getWeight() { return weight; }
    }

    private void resetActionOnMfaSuccess(String userId, HttpServletRequest request) {
        if (userId == null || userId.isBlank() || redisTemplate == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            // 1. previousAction 저장 (LLM CHALLENGE MFA 구분용 - AI Native v6.8)
            // - previousAction이 "CHALLENGE"이면 LLM CHALLENGE MFA
            // - 그 외(null, "ALLOW")면 일반 MFA (정책 기반)
            Object previousAction = redisTemplate.opsForHash().get(analysisKey, "action");
            redisTemplate.opsForHash().put(analysisKey, "previousAction",
                    previousAction != null ? previousAction.toString() : "NONE");

            // 2. action을 ALLOW로 변경
            redisTemplate.opsForHash().put(analysisKey, "action", "ALLOW");

            // 3. TTL을 ALLOW의 TTL(1시간)로 갱신
            redisTemplate.expire(analysisKey, Duration.ofSeconds(60));

            // 4. Baseline 학습 수행 (ALLOW 획득 지점에서 직접 처리)
            learnBaselineOnMfaSuccess(userId, request);

            log.info("[MFA][AI Native v6.8] Action set to ALLOW with previousAction={} for user: {}",
                    previousAction, userId);

        } catch (Exception e) {
            log.error("[MFA] Failed to set action to ALLOW for user: {}", userId, e);
        }
    }

    private void learnBaselineOnMfaSuccess(String userId, HttpServletRequest request) {
        if (baselineLearningService == null) {
            log.debug("[MFA] BaselineLearningService not available, skipping baseline learning");
            return;
        }
        try {
            SecurityDecision decision = SecurityDecision.builder()
                    .action(SecurityDecision.Action.ALLOW)
                    .confidence(1.0)  // MFA 성공 = 최고 신뢰도
                    .riskScore(0.0)   // MFA 성공 = 최저 위험도
                    .reasoning("MFA authentication completed successfully")
                    .build();

            // SecurityEvent 생성 (request에서 컨텍스트 추출)
            SecurityEvent event = SecurityEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .source(SecurityEvent.EventSource.IAM)
                    .userId(userId)
                    .sourceIp(extractClientIp(request))
                    .sessionId(request.getSession(false) != null ?
                            request.getSession(false).getId() : null)
                    .userAgent(request.getHeader("User-Agent"))
                    .timestamp(LocalDateTime.now())
                    .description("MFA authentication success - baseline learning")
                    .build();

            // Baseline 학습 수행
            boolean learned = baselineLearningService.learnIfNormal(userId, decision, event);

            if (learned) {
                log.info("[MFA][Baseline] Baseline learned on MFA success: userId={}", userId);
            } else {
                log.debug("[MFA][Baseline] Baseline learning skipped: userId={}", userId);
            }

        } catch (Exception e) {
            log.warn("[MFA][Baseline] Failed to learn baseline on MFA success: userId={}", userId, e);
            // Baseline 학습 실패해도 MFA 성공 처리는 계속 진행
        }
    }

    private void publishAuthenticationSuccessEvent(HttpServletRequest request,
                                                   Authentication authentication) {
        try {
            if (eventPublisher == null) {
                log.debug("ApplicationEventPublisher not available, skipping event publication");
                return;
            }

            UnifiedCustomUserDetails userDto = (UnifiedCustomUserDetails) authentication.getPrincipal();

            // 이벤트 빌더 생성
            AuthenticationSuccessEvent.AuthenticationSuccessEventBuilder builder =
                    AuthenticationSuccessEvent.builder()
                            .eventId(java.util.UUID.randomUUID().toString())
                            .userId(userDto.getUsername())  // Zero Trust를 위한 사용자 식별자 (username)
                            .username(userDto.getUsername())
                            .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                            .eventTimestamp(java.time.LocalDateTime.now())
                            .sourceIp(extractClientIp(request))
                            .userAgent(request.getHeader("User-Agent"))
                            .authenticationType("MFA");

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("requestPath", request.getRequestURI());
            metadata.put("httpMethod", request.getMethod());
            builder.metadata(metadata);

            // 이벤트 발행
            AuthenticationSuccessEvent event = builder.build();
            eventPublisher.publishEvent(event);

            log.debug("Published authentication success event for user: {}, eventId: {}",
                    userDto.getUsername(), event.getEventId());

        } catch (Exception e) {
            // 이벤트 발행 실패가 인증 프로세스를 중단시키지 않도록 예외 처리
            log.error("Failed to publish authentication success event", e);
        }
    }
    protected String extractClientIp(HttpServletRequest request) {
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
}