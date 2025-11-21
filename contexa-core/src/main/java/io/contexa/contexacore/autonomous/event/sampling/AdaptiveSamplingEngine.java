package io.contexa.contexacore.autonomous.event.sampling;

import io.contexa.contexacore.autonomous.event.decision.EventTier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Random;

/**
 * Adaptive Sampling Engine (통합 버전)
 *
 * 시스템 상태와 공격 모드에 따라 동적으로 샘플링 비율을 조정합니다.
 *
 * 샘플링 조정 요소:
 * 1. Tier별 기본 샘플링 비율 (EventTier)
 * 2. 시스템 부하 (Redis: system:load:current)
 * 3. 공격 모드 (Redis: system:attack:mode)
 *    - NORMAL: 1.0x (변화 없음)
 *    - SUSPECTED: 2.0x (샘플링 2배 증가)
 *    - CONFIRMED: 3.0x (샘플링 3배 증가)
 *
 * 일관성:
 * - IP 기반 (익명 사용자): 동일 IP는 항상 동일한 샘플링 결정
 * - UserId 기반 (인증 사용자): 동일 사용자는 항상 동일한 샘플링 결정
 * - 해시값을 시드로 사용
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class AdaptiveSamplingEngine {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;

    /**
     * Redis 키
     */
    private static final String KEY_SYSTEM_LOAD = "system:load:current";
    private static final String KEY_ATTACK_MODE = "system:attack:mode";

    /**
     * 공격 모드
     */
    private static final String ATTACK_MODE_NORMAL = "NORMAL";
    private static final String ATTACK_MODE_SUSPECTED = "SUSPECTED";
    private static final String ATTACK_MODE_CONFIRMED = "CONFIRMED";

    /**
     * 샘플링 여부 결정 (통합 버전)
     *
     * @param tier 이벤트 Tier (Risk Score 기반)
     * @param identifier 식별자 (IP 또는 UserId - 일관성 있는 샘플링용)
     * @return true면 발행, false면 스킵
     */
    public boolean shouldSample(EventTier tier, String identifier) {
        // 1. CRITICAL Tier는 항상 100% 발행
        if (tier.requiresImmediatePublishing()) {
            return true;
        }

        // 2. 적응형 샘플링 비율 계산
        double samplingRate = calculateAdaptiveSamplingRate(tier);

        // 3. Identifier 기반 일관성 있는 샘플링 (동일 ID = 동일 결정)
        boolean shouldSample = identifierBasedSampling(identifier, samplingRate);

        log.debug("[AdaptiveSamplingEngine] Tier: {}, SamplingRate: {:.3f}, Decision: {}, Identifier: {}",
                tier, samplingRate, shouldSample, identifier);

        return shouldSample;
    }

    /**
     * 적응형 샘플링 비율 계산 (통합 버전)
     *
     * 기본 비율 × 시스템 부하 계수 × 공격 모드 계수
     *
     * @param tier 이벤트 Tier (Risk Score 기반)
     * @return 조정된 샘플링 비율 (0.0 ~ 1.0)
     */
    private double calculateAdaptiveSamplingRate(EventTier tier) {
        // 1. Tier별 기본 샘플링 비율
        double baseRate = tier.getBaseSamplingRate();

        // 2. 시스템 부하 계수 (부하 높으면 샘플링 감소)
        double systemLoadFactor = getSystemLoadFactor();

        // 3. 공격 모드 계수 (공격 모드면 샘플링 증가)
        double attackModeFactor = getAttackModeFactor();

        // 4. 최종 샘플링 비율
        double adaptiveRate = baseRate * systemLoadFactor * attackModeFactor;

        // 5. 범위 제한 (0.0 ~ 1.0)
        return Math.max(0.0, Math.min(1.0, adaptiveRate));
    }

    /**
     * 시스템 부하 계수
     *
     * 시스템 부하가 높을수록 샘플링 감소
     *
     * @return 조정 계수 (0.5 ~ 1.0)
     */
    private double getSystemLoadFactor() {
        try {
            Double systemLoad = (Double) redisTemplate.opsForValue().get(KEY_SYSTEM_LOAD);

            if (systemLoad == null) {
                return 1.0;  // 부하 정보 없으면 기본값
            }

            // 부하가 높을수록 샘플링 감소
            if (systemLoad > 0.9) {
                return 0.5;  // 90% 이상: 50% 감소
            } else if (systemLoad > 0.75) {
                return 0.7;  // 75-90%: 30% 감소
            } else if (systemLoad > 0.6) {
                return 0.9;  // 60-75%: 10% 감소
            } else {
                return 1.0;  // 60% 이하: 감소 없음
            }

        } catch (Exception e) {
            log.warn("[AdaptiveSamplingEngine] Failed to get system load", e);
            return 1.0;
        }
    }

    /**
     * 공격 모드 계수
     *
     * 공격 모드일수록 샘플링 증가
     *
     * @return 조정 계수 (1.0 ~ 3.0)
     */
    private double getAttackModeFactor() {
        try {
            String attackMode = (String) redisTemplate.opsForValue().get(KEY_ATTACK_MODE);

            if (attackMode == null) {
                attackMode = ATTACK_MODE_NORMAL;
            }

            return switch (attackMode) {
                case ATTACK_MODE_CONFIRMED -> 3.0;  // 공격 확정: 3배 증가
                case ATTACK_MODE_SUSPECTED -> 2.0;  // 공격 의심: 2배 증가
                default -> 1.0;  // 정상 모드: 증가 없음
            };

        } catch (Exception e) {
            log.warn("[AdaptiveSamplingEngine] Failed to get attack mode", e);
            return 1.0;
        }
    }

    /**
     * Identifier 기반 일관성 있는 샘플링 (통합 버전)
     *
     * 동일 Identifier는 항상 동일한 샘플링 결정을 받음
     * Identifier 해시값을 시드로 사용하여 Random 생성
     *
     * @param identifier 식별자 (IP 또는 UserId)
     * @param samplingRate 샘플링 비율
     * @return true면 샘플링 대상
     */
    private boolean identifierBasedSampling(String identifier, double samplingRate) {
        if (identifier == null) {
            // Identifier 없으면 일반 Random 사용
            return Math.random() < samplingRate;
        }

        // Identifier 해시값을 시드로 사용 (동일 ID = 동일 시드 = 동일 결정)
        long seed = identifier.hashCode();
        Random random = new Random(seed);

        return random.nextDouble() < samplingRate;
    }
}
