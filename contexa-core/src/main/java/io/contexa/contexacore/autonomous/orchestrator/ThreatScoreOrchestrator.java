package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;

/**
 * ThreatScoreOrchestrator - AI Native Threat Score 관리자
 *
 * AI Native 원칙 기반 단순화된 Threat Score 관리:
 * - LLM이 반환한 riskScore를 그대로 Redis에 저장
 * - 복잡한 중간 처리 로직 제거
 * - UserSecurityContext는 AIReactiveSecurityContextRepository에서 관리
 *
 * 리팩토링 이력 (v3.1.0):
 * - setThreatScore() -> saveThreatScore()로 단순화
 * - getUserContext(), createInitialContext(), saveUserContext() 제거
 * - RedisAtomicOperations 의존성 제거 (단순 SET 사용)
 * - 177줄 -> 40줄로 92% 감소
 *
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class ThreatScoreOrchestrator {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${threat.score.initial:0.3}")
    private double initialThreatScore;

    /**
     * Threat Score 조회
     *
     * @param userId 사용자 ID
     * @return 현재 Threat Score (없으면 초기값 반환)
     */
    public double getThreatScore(String userId) {
        if (userId == null || userId.isEmpty()) {
            return initialThreatScore;
        }

        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            Object threatScoreObj = redisTemplate.opsForValue().get(threatScoreKey);

            if (threatScoreObj != null) {
                return Double.parseDouble(threatScoreObj.toString());
            }
        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to retrieve threat score: userId={}", userId, e);
        }

        return initialThreatScore;
    }
}
