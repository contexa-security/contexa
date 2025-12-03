package io.contexa.contexaiam.security.core.zerotrust;

import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

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

    @Value("${zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${zerotrust.threat.initial:0.3}")
    private double initialThreatScore;

    @Value("${zerotrust.threat.threshold.high:0.7}")
    private double highThreatThreshold;

    @Value("${zerotrust.threat.threshold.critical:0.9}")
    private double criticalThreatThreshold;

    @Value("${zerotrust.cache.ttl.hours:24}")
    private long cacheTtlHours;

    @Value("${zerotrust.session.tracking.enabled:true}")
    private boolean sessionTrackingEnabled;

    /**
     * SecurityContext에 Zero Trust 기능 적용 (인증된 사용자)
     *
     * @param context SecurityContext
     * @param userId 사용자 ID
     * @param sessionId 세션 ID (옵션)
     */
    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId) {
        if (!zeroTrustEnabled || context == null || userId == null) {
            return;
        }

        try {
            // AI Native: LLM이 결정한 action 조회
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
            adjustAuthoritiesByAction(context, action, userId);

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

            // Threat Score 증가 (보안 이벤트)
            if (userId != null && reason.contains("security")) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("sessionId", sessionId);
                metadata.put("event", "session_invalidation");

                threatScoreOrchestrator.updateThreatScore(userId, 0.1,
                    "Session invalidated: " + reason, metadata);
            }

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
     * 2. LLM action 조회 (ColdPathEventProcessor가 저장)
     * 3. 키 없음 → ALLOW (기본값)
     *
     * @param userId 사용자 ID
     * @return action 문자열 (ALLOW, MONITOR, INVESTIGATE, CHALLENGE, BLOCK)
     */
    private String getLatestAction(String userId) {
        try {
            // 1. 차단 상태 확인 (RealtimeBlockStrategy가 저장)
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            Boolean isBlocked = (Boolean) redisTemplate.opsForValue().get(blockKey);
            if (Boolean.TRUE.equals(isBlocked)) {
                return "BLOCK";
            }

            // 2. LLM action 조회 (ColdPathEventProcessor가 저장)
            String actionKey = ZeroTrustRedisKeys.userAction(userId);
            Object action = redisTemplate.opsForValue().get(actionKey);
            return action != null ? action.toString() : "ALLOW";

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get action for user: {}", userId, e);
            return "ALLOW";  // Fail-safe: 기본값 반환
        }
    }

    /**
     * AI Native: action 기반 권한 동적 조정
     *
     * 임계값 기반 판단 완전 제거 - LLM이 결정한 action을 직접 사용
     *
     * @param context SecurityContext
     * @param action LLM이 결정한 action
     * @param userId 사용자 ID
     */
    private void adjustAuthoritiesByAction(SecurityContext context, String action, String userId) {
        Authentication auth = context.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        Collection<? extends GrantedAuthority> currentAuthorities = auth.getAuthorities();
        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>(currentAuthorities);

        switch (action) {
            case "ALLOW" -> {
                // 정상 - 권한 유지
            }
            case "BLOCK" -> {
                adjustedAuthorities.clear();
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_BLOCKED"));
                log.warn("[ZeroTrust][AI Native] User BLOCKED: {}", userId);
            }
            case "CHALLENGE" -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_MFA_REQUIRED"));
                log.info("[ZeroTrust][AI Native] MFA CHALLENGE required: {}", userId);
            }
            case "INVESTIGATE", "ESCALATE" -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_REVIEW_REQUIRED"));
                log.warn("[ZeroTrust][AI Native] Security REVIEW required: {}", userId);
            }
            case "MONITOR" -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_MONITORED"));
                // Silent monitoring - 사용자 모름
            }
            default -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_LIMITED"));
                log.warn("[ZeroTrust][AI Native] Unknown action '{}': {}", action, userId);
            }
        }

        // 권한이 변경된 경우 업데이트
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
        if (context.getAuthentication() instanceof ZeroTrustAuthenticationToken) {
            ZeroTrustAuthenticationToken zeroTrustAuth =
                (ZeroTrustAuthenticationToken) context.getAuthentication();

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
     * Threat Score 업데이트
     *
     * @param userId 사용자 ID
     * @param adjustment 조정값 (양수: 위협 증가, 음수: 위협 감소)
     * @param reason 사유
     * @return 업데이트된 Threat Score
     */
    public double updateThreatScore(String userId, double adjustment, String reason) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", System.currentTimeMillis());
        metadata.put("source", "ZeroTrustSecurityService");

        return threatScoreOrchestrator.updateThreatScore(userId, adjustment, reason, metadata);
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
     * Trust Tier 결정
     *
     * @param threatScore 위협 점수
     * @return Trust Tier
     */
    public TrustTier getTrustTier(double threatScore) {
        if (threatScore >= criticalThreatThreshold) {
            return TrustTier.UNTRUSTED;
        } else if (threatScore >= highThreatThreshold) {
            return TrustTier.LOW;
        } else if (threatScore >= 0.5) {
            return TrustTier.MEDIUM;
        } else if (threatScore >= 0.3) {
            return TrustTier.HIGH;
        } else {
            return TrustTier.FULL;
        }
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
}