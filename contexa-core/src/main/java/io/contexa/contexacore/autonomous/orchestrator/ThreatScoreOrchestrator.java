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
     * AI Native: Threat Score 직접 설정 (시간 감쇠 없음)
     *
     * LLM이 반환한 riskScore를 그대로 Redis에 저장합니다.
     * 기존 누적 방식(updateThreatScore)과 달리, 직접 설정 방식으로 동작합니다.
     *
     * AI Native 원칙:
     * - LLM 판단을 100% 신뢰
     * - 시간 감쇠(decay) 없음
     * - ±0.15 제한 없음
     * - 누적이 아닌 덮어쓰기
     *
     * 용도:
     * - Cold Path에서 LLM 분석 완료 후 호출
     * - ALLOW/BLOCK/STEP_UP 판정의 근거가 되는 riskScore 저장
     *
     * @param userId 사용자 ID
     * @param riskScore LLM이 반환한 위험 점수 (0.0 ~ 1.0, 가공 없이 그대로 사용)
     * @param reason 설정 이유 (감사 로그용)
     * @param metadata 추가 메타데이터
     * @return 저장된 Threat Score
     */
    public double setThreatScore(String userId, double riskScore, String reason, Map<String, Object> metadata) {
        if (userId == null || userId.isEmpty()) {
            log.warn("[ThreatScoreOrchestrator] Invalid userId provided for setThreatScore");
            return riskScore;
        }

        try {
            // 현재 Threat Score 조회 (로깅용)
            double currentThreatScore = getThreatScore(userId);

            // 컨텍스트 준비
            UserSecurityContext userContext = getUserContext(userId);
            if (userContext == null) {
                userContext = createInitialContext(userId);
            }

            // 컨텍스트 업데이트
            userContext.setUpdatedAt(LocalDateTime.now());
            userContext.addThreatIndicator("lastUpdateReason", reason);
            userContext.addThreatIndicator("aiNative", "true");
            userContext.addThreatIndicator("llmRiskScore", String.valueOf(riskScore));
            userContext.setCurrentThreatScore(riskScore);

            String contextJson = objectMapper.writeValueAsString(userContext);

            // AI Native: Redis 직접 설정 (시간 감쇠 없음)
            double savedScore = redisAtomicOperations.setThreatScoreDirectly(
                userId, riskScore, contextJson, (int) cacheTtlHours
            );

            log.info("[ThreatScoreOrchestrator][AI Native] Threat Score directly set - User: {}, {} → {} (LLM riskScore: {}), Reason: {}",
                userId, String.format("%.3f", currentThreatScore), String.format("%.3f", savedScore),
                String.format("%.3f", riskScore), reason);

            return savedScore;

        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to set Threat Score directly for user: {}", userId, e);
            // 예외 시에도 riskScore 반환 (LLM 판단 유지)
            return riskScore;
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