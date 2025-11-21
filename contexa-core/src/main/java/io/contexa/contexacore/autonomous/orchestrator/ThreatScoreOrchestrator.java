package io.contexa.contexacore.autonomous.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * ThreatScoreOrchestrator - 중앙집중식 Threat Score 관리자
 *
 * 모든 Threat Score 업데이트를 중앙에서 관리하여 일관성과 원자성을 보장합니다.
 * Redis를 통한 분산 환경에서의 동시성 제어를 제공합니다.
 * UserSecurityContext를 관리하여 SessionThreatEvaluationStrategy와 통합됩니다.
 *
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class ThreatScoreOrchestrator {

    private final RedisAtomicOperations redisAtomicOperations;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${threat.score.initial:0.3}")
    private double initialThreatScore;

    @Value("${threat.score.min:0.0}")
    private double minThreatScore;

    @Value("${threat.score.max:1.0}")
    private double maxThreatScore;

    @Value("${threat.score.cache.ttl.hours:24}")
    private long cacheTtlHours;

    /**
     * Threat Score 업데이트 - 메인 메서드
     *
     * 원자적 연산으로 Threat Score를 업데이트하고 UserSecurityContext를 관리합니다.
     *
     * @param userId 사용자 ID
     * @param threatAdjustment 조정값 (양수: 위협 증가, 음수: 위협 감소)
     * @param reason 업데이트 이유
     * @param metadata 추가 메타데이터
     * @return 업데이트된 Threat Score
     */
    public double updateThreatScore(String userId, double threatAdjustment, String reason, Map<String, Object> metadata) {
        if (userId == null || userId.isEmpty()) {
            log.warn("[ThreatScoreOrchestrator] Invalid userId provided");
            return initialThreatScore;
        }

        try {
            // 3. 컨텍스트 준비 및 업데이트
            UserSecurityContext userContext = getUserContext(userId);
            if (userContext == null) {
                userContext = createInitialContext(userId);
            }

            // 현재 Threat Score 조회 (로깅용)
            double currentThreatScore = getThreatScore(userId);

            // 컨텍스트 업데이트
            userContext.setUpdatedAt(LocalDateTime.now());
            userContext.addThreatIndicator("lastUpdateReason", reason);
            userContext.setCurrentThreatScore(currentThreatScore); // 현재값 설정

            String contextJson = objectMapper.writeValueAsString(userContext);

            // 4. Redis 원자적 업데이트 (컨텍스트 포함 저장, 범위 검증 포함)
            double newThreatScore = redisAtomicOperations.updateThreatScoreWithContext(
                userId, threatAdjustment, contextJson, (int) cacheTtlHours
            );

            log.info("[ThreatScoreOrchestrator] Threat Score updated - User: {}, {} -> {} (adjustment: {}), Reason: {}",
                userId, String.format("%.3f", currentThreatScore), String.format("%.3f", newThreatScore),
                threatAdjustment, reason);

            return newThreatScore;

        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to update Threat Score for user: {}", userId, e);
            return initialThreatScore;
        }
    }

    /**
     * Threat Score 조회
     *
     * @param userId 사용자 ID
     * @return 현재 Threat Score
     */
    public double getThreatScore(String userId) {
        if (userId == null || userId.isEmpty()) {
            return initialThreatScore;
        }

        // Redis 에서 조회 (ZeroTrustRedisKeys 사용)
        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            Object threatScoreObj = redisTemplate.opsForValue().get(threatScoreKey);

            if (threatScoreObj != null) {
                return Double.parseDouble(threatScoreObj.toString());
            }
        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to retrieve Threat Score for user: {}", userId, e);
        }

        // 기본값 반환
        return initialThreatScore;
    }


    /**
     * 사용자 컨텍스트 조회
     */
    private UserSecurityContext getUserContext(String userId) {
        try {
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            return (UserSecurityContext) redisTemplate.opsForValue().get(contextKey);
        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to get user context for: {}", userId, e);
            return null;
        }
    }

    /**
     * 초기 사용자 컨텍스트 생성
     */
    private UserSecurityContext createInitialContext(String userId) {
        return UserSecurityContext.builder()
            .userId(userId)
            .currentThreatScore(initialThreatScore)
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .build();
    }

    /**
     * 사용자 컨텍스트 저장
     */
    private void saveUserContext(String userId, UserSecurityContext context) {
        try {
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            redisTemplate.opsForValue().set(contextKey, context, Duration.ofHours(cacheTtlHours));
        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to save user context for: {}", userId, e);
        }
    }



}