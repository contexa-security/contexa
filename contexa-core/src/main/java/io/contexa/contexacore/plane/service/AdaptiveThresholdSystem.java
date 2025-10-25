package io.contexa.contexacore.plane.service;

import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * 적응형 임계값 시스템 (CUSUM 기반)
 *
 * CUSUM (Cumulative Sum) 알고리즘을 사용하여 베이스라인 변화를 탐지합니다.
 * 정상 행동 패턴이 점진적으로 변화할 때 임계값을 자동으로 조정합니다.
 *
 * 핵심 기능:
 * 1. CUSUM 기반 베이스라인 드리프트 탐지
 * 2. 신뢰 점수 기반 임계값 동적 조정
 * 3. 점진적 학습 (Incremental Learning)
 *
 * 외부기관 2 피드백 반영:
 * - "임계값 auto-tuning이 필요합니다"
 * - CUSUM으로 정상 행동의 점진적 변화 감지
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
@Service
public class AdaptiveThresholdSystem {

    @Autowired
    @Qualifier("generalRedisTemplate")
    private RedisTemplate<String, Object> redisTemplate;

    // ===== CUSUM 파라미터 (application.yml에서 주입) =====

    /**
     * CUSUM 탐지 임계값 (기본: 5.0)
     * 이 값을 초과하면 베이스라인 변화로 판단
     */
    @Value("${hcad.adaptive.cusum.threshold:5.0}")
    private double cusumThreshold;

    /**
     * CUSUM 슬랙 파라미터 (기본: 0.5)
     * 정상 범위 허용 오차
     */
    @Value("${hcad.adaptive.cusum.slack:0.5}")
    private double cusumSlack;

    /**
     * 베이스라인 업데이트 윈도우 (기본: 100)
     * 이 횟수만큼 관찰 후 베이스라인 재계산
     */
    @Value("${hcad.adaptive.baseline.window:100}")
    private int baselineWindow;

    /**
     * 최소 신뢰 점수 (기본: 0.7)
     * 이 값 이상이어야 베이스라인에 반영
     */
    @Value("${hcad.adaptive.min.trust.score:0.7}")
    private double minTrustScore;

    /**
     * 임계값 조정 비율 (기본: 0.1)
     * 베이스라인 변화 시 임계값 조정 폭 (10%)
     */
    @Value("${hcad.adaptive.adjustment.rate:0.1}")
    private double adjustmentRate;

    // ===== Public Methods =====

    /**
     * 신호 값과 신뢰 점수를 CUSUM에 업데이트하고 베이스라인 변화 탐지
     *
     * @param userId 사용자 ID
     * @param signalType 신호 타입 (예: "network", "crypto", "timing")
     * @param value 신호 값 (0.0~1.0)
     * @param trustScore 신뢰 점수 (0.0~1.0)
     * @return BaselineChangeResult (변화 감지 여부 및 새 임계값)
     */
    public BaselineChangeResult updateAndDetectChange(
            String userId,
            String signalType,
            double value,
            double trustScore) {

        if (trustScore < minTrustScore) {
            // 신뢰 점수가 낮으면 무시
            log.debug("[AdaptiveThreshold] Low trust score {}, skipping update for user {} signal {}",
                    trustScore, userId, signalType);
            return BaselineChangeResult.noChange();
        }

        // 1. 현재 베이스라인 및 CUSUM 상태 조회
        CusumState state = getCusumState(userId, signalType);

        // 2. CUSUM 업데이트
        double diff = value - state.getBaseline();
        double newCusumPlus = Math.max(0, state.getCusumPlus() + diff - cusumSlack);
        double newCusumMinus = Math.max(0, state.getCusumMinus() - diff - cusumSlack);

        // 3. 베이스라인 변화 탐지
        boolean changeDetected = (newCusumPlus > cusumThreshold) || (newCusumMinus > cusumThreshold);

        // 4. 관찰 이력 업데이트
        addObservation(userId, signalType, value, trustScore);

        if (changeDetected) {
            // 베이스라인 변화 감지 → 재계산
            double newBaseline = recalculateBaseline(userId, signalType);
            double newThreshold = calculateNewThreshold(state.getCurrentThreshold(), newBaseline, state.getBaseline());

            // CUSUM 리셋
            saveCusumState(userId, signalType, newBaseline, newThreshold, 0.0, 0.0);

            log.info("[AdaptiveThreshold] Baseline change detected for user {} signal {}: {} → {} (threshold: {} → {})",
                    userId, signalType,
                    String.format("%.3f", state.getBaseline()),
                    String.format("%.3f", newBaseline),
                    String.format("%.3f", state.getCurrentThreshold()),
                    String.format("%.3f", newThreshold));

            return BaselineChangeResult.builder()
                    .changeDetected(true)
                    .oldBaseline(state.getBaseline())
                    .newBaseline(newBaseline)
                    .oldThreshold(state.getCurrentThreshold())
                    .newThreshold(newThreshold)
                    .observationCount(state.getObservationCount() + 1)
                    .build();
        } else {
            // 변화 없음 → CUSUM 상태만 업데이트
            saveCusumState(userId, signalType, state.getBaseline(), state.getCurrentThreshold(), newCusumPlus, newCusumMinus);

            return BaselineChangeResult.noChange();
        }
    }

    /**
     * 특정 신호의 현재 동적 임계값 조회
     *
     * @param userId 사용자 ID
     * @param signalType 신호 타입
     * @return 현재 임계값 (없으면 기본값 0.5)
     */
    public double getCurrentThreshold(String userId, String signalType) {
        CusumState state = getCusumState(userId, signalType);
        return state.getCurrentThreshold();
    }

    /**
     * CUSUM 상태 초기화 (테스트용)
     */
    public void resetCusumState(String userId, String signalType) {
        String cusumKey = buildCusumKey(userId, signalType);
        String observationKey = buildObservationKey(userId, signalType);

        redisTemplate.delete(cusumKey);
        redisTemplate.delete(observationKey);

        log.info("[AdaptiveThreshold] Reset CUSUM state for user {} signal {}", userId, signalType);
    }

    // ===== Private Methods =====

    /**
     * CUSUM 상태 조회
     */
    private CusumState getCusumState(String userId, String signalType) {
        String key = buildCusumKey(userId, signalType);

        @SuppressWarnings("unchecked")
        CusumState state = (CusumState) redisTemplate.opsForValue().get(key);

        if (state == null) {
            // 초기 상태 생성
            state = CusumState.builder()
                    .baseline(0.5) // 초기 베이스라인 (중립)
                    .currentThreshold(0.5) // 초기 임계값
                    .cusumPlus(0.0)
                    .cusumMinus(0.0)
                    .observationCount(0)
                    .build();
        }

        return state;
    }

    /**
     * CUSUM 상태 저장
     */
    private void saveCusumState(String userId, String signalType, double baseline, double threshold,
                                double cusumPlus, double cusumMinus) {
        String key = buildCusumKey(userId, signalType);

        CusumState state = getCusumState(userId, signalType);

        CusumState newState = CusumState.builder()
                .baseline(baseline)
                .currentThreshold(threshold)
                .cusumPlus(cusumPlus)
                .cusumMinus(cusumMinus)
                .observationCount(state.getObservationCount() + 1)
                .lastUpdated(LocalDateTime.now())
                .build();

        redisTemplate.opsForValue().set(key, newState);
    }

    /**
     * 관찰값 추가 (최근 N개 유지)
     */
    private void addObservation(String userId, String signalType, double value, double trustScore) {
        String key = buildObservationKey(userId, signalType);

        Observation obs = Observation.builder()
                .value(value)
                .trustScore(trustScore)
                .timestamp(LocalDateTime.now())
                .build();

        redisTemplate.opsForList().rightPush(key, obs);

        // 윈도우 크기 유지
        Long size = redisTemplate.opsForList().size(key);
        if (size != null && size > baselineWindow) {
            redisTemplate.opsForList().leftPop(key);
        }
    }

    /**
     * 베이스라인 재계산 (최근 관찰값의 가중 평균)
     */
    private double recalculateBaseline(String userId, String signalType) {
        String key = buildObservationKey(userId, signalType);

        @SuppressWarnings("unchecked")
        List<Observation> observations = (List<Observation>) (List<?>) redisTemplate.opsForList().range(key, 0, -1);

        if (observations == null || observations.isEmpty()) {
            return 0.5; // 기본값
        }

        // 신뢰 점수 기반 가중 평균
        double weightedSum = 0.0;
        double totalWeight = 0.0;

        for (Observation obs : observations) {
            if (obs.getTrustScore() >= minTrustScore) {
                weightedSum += obs.getValue() * obs.getTrustScore();
                totalWeight += obs.getTrustScore();
            }
        }

        if (totalWeight == 0) {
            return 0.5; // 기본값
        }

        return weightedSum / totalWeight;
    }

    /**
     * 새 임계값 계산
     *
     * 베이스라인 변화에 비례하여 임계값 조정
     */
    private double calculateNewThreshold(double oldThreshold, double newBaseline, double oldBaseline) {
        double baselineChange = newBaseline - oldBaseline;
        double adjustment = baselineChange * adjustmentRate;

        double newThreshold = oldThreshold + adjustment;

        // 임계값 범위 제한 [0.1, 0.9]
        return Math.max(0.1, Math.min(0.9, newThreshold));
    }

    /**
     * Redis 키 생성
     */
    private String buildCusumKey(String userId, String signalType) {
        return String.format("hcad:adaptive:cusum:%s:%s", signalType, userId);
    }

    private String buildObservationKey(String userId, String signalType) {
        return String.format("hcad:adaptive:observation:%s:%s", signalType, userId);
    }

    // ===== Inner Classes =====

    /**
     * CUSUM 상태
     */
    @Getter
    @Builder
    public static class CusumState implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private final double baseline;           // 현재 베이스라인
        private final double currentThreshold;   // 현재 임계값
        private final double cusumPlus;          // CUSUM+ (상향 변화)
        private final double cusumMinus;         // CUSUM- (하향 변화)
        private final int observationCount;      // 관찰 횟수
        private final LocalDateTime lastUpdated; // 마지막 업데이트 시간
    }

    /**
     * 관찰값
     */
    @Getter
    @Builder
    public static class Observation implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private final double value;              // 신호 값
        private final double trustScore;         // 신뢰 점수
        private final LocalDateTime timestamp;   // 관찰 시간
    }

    /**
     * 베이스라인 변화 결과
     */
    @Getter
    @Builder
    public static class BaselineChangeResult {
        private final boolean changeDetected;    // 변화 감지 여부
        private final double oldBaseline;        // 이전 베이스라인
        private final double newBaseline;        // 새 베이스라인
        private final double oldThreshold;       // 이전 임계값
        private final double newThreshold;       // 새 임계값
        private final int observationCount;      // 관찰 횟수

        public static BaselineChangeResult noChange() {
            return BaselineChangeResult.builder()
                    .changeDetected(false)
                    .oldBaseline(0.0)
                    .newBaseline(0.0)
                    .oldThreshold(0.0)
                    .newThreshold(0.0)
                    .observationCount(0)
                    .build();
        }
    }
}
