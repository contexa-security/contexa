package io.contexa.contexacore.plane.service;

import io.contexa.contexacore.plane.service.OrthogonalSignalCollector.OrthogonalSignals;
import io.contexa.contexacore.plane.service.SignalInconsistencyDetector.InconsistencyResult;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 누적 위험 계산기 (7-Signal 기반)
 *
 * 7차원 직교 신호를 종합하여 최종 누적 위험 점수를 계산합니다.
 * 외부기관 2 피드백에서 요구한 "정교한 누적 위험 계산"을 구현합니다.
 *
 * 핵심 기능:
 * 1. 7차원 신호 가중 합산
 * 2. 신호 불일치 패널티 적용
 * 3. HCAD Layer 3 경고 누적
 * 4. 시간 기반 감쇠 (Time Decay)
 *
 * 외부기관 2 피드백 반영:
 * - "단순히 Layer3 경고만 보는 것이 아닌 정교한 누적 위험 계산 필요"
 * - 7-signal 종합 분석 + 불일치 패널티 + 시간 감쇠
 *
 * @author AI3Security
 * @since 3.0
 */
@Slf4j
@Service
public class AccumulatedRiskCalculator {

    // ===== 신호별 가중치 (application.yml에서 주입) =====

    /**
     * HCAD Layer 1~4 가중치 (기본: 각 0.1, 합 0.4)
     */
    @Value("${risk.weight.layer1:0.1}")
    private double weightLayer1;

    @Value("${risk.weight.layer2:0.1}")
    private double weightLayer2;

    @Value("${risk.weight.layer3:0.1}")
    private double weightLayer3;

    @Value("${risk.weight.layer4:0.1}")
    private double weightLayer4;

    /**
     * Orthogonal Signal 가중치 (기본: 각 0.2, 합 0.6)
     */
    @Value("${risk.weight.network:0.2}")
    private double weightNetwork;

    @Value("${risk.weight.crypto:0.2}")
    private double weightCrypto;

    @Value("${risk.weight.timing:0.2}")
    private double weightTiming;

    /**
     * 신호 불일치 패널티 (기본: 0.3)
     * 불일치 감지 시 위험 점수에 추가
     */
    @Value("${risk.penalty.inconsistency:0.3}")
    private double inconsistencyPenalty;

    /**
     * Layer3 경고 패널티 (기본: 0.2)
     * Layer3 threshold 초과 시 추가 패널티
     */
    @Value("${risk.penalty.layer3.warning:0.2}")
    private double layer3WarningPenalty;

    /**
     * Layer3 경고 임계값 (기본: 0.7)
     */
    @Value("${risk.threshold.layer3.warning:0.7}")
    private double layer3WarningThreshold;

    /**
     * 시간 감쇠 계수 (기본: 0.9)
     * 이전 위험 점수에 곱해짐 (시간 경과에 따라 감소)
     */
    @Value("${risk.decay.factor:0.9}")
    private double decayFactor;

    // ===== Public Methods =====

    /**
     * 7-signal 기반 누적 위험 점수 계산
     *
     * @param signals 7차원 직교 신호
     * @param inconsistency 신호 불일치 결과
     * @param previousRisk 이전 위험 점수 (시간 감쇠 적용)
     * @return AccumulatedRiskResult
     */
    public AccumulatedRiskResult calculateAccumulatedRisk(
            OrthogonalSignals signals,
            InconsistencyResult inconsistency,
            double previousRisk) {

        // 1. 7차원 신호 가중 합산
        double baseRisk = calculateBaseRisk(signals);

        // 2. 신호 불일치 패널티
        double inconsistencyScore = 0.0;
        if (inconsistency != null && inconsistency.isInconsistent()) {
            inconsistencyScore = inconsistencyPenalty;
        }

        // 3. Layer3 경고 패널티
        double layer3WarningScore = 0.0;
        if (signals.getLayer3Signal() > layer3WarningThreshold) {
            layer3WarningScore = layer3WarningPenalty;
        }

        // 4. 시간 기반 감쇠 적용 (이전 위험 점수)
        double decayedPreviousRisk = previousRisk * decayFactor;

        // 5. 최종 누적 위험 점수 계산
        double accumulatedRisk = baseRisk + inconsistencyScore + layer3WarningScore + decayedPreviousRisk;

        // 6. 범위 제한 [0.0, 1.0]
        accumulatedRisk = Math.max(0.0, Math.min(1.0, accumulatedRisk));

        // 7. 위험 레벨 판정
        RiskLevel riskLevel = determineRiskLevel(accumulatedRisk);

        log.debug("[AccumulatedRisk] Base: {}, Inconsistency: {}, Layer3: {}, Decayed: {}, Total: {} ({})",
                String.format("%.3f", baseRisk),
                String.format("%.3f", inconsistencyScore),
                String.format("%.3f", layer3WarningScore),
                String.format("%.3f", decayedPreviousRisk),
                String.format("%.3f", accumulatedRisk),
                riskLevel);

        return AccumulatedRiskResult.builder()
                .accumulatedRisk(accumulatedRisk)
                .baseRisk(baseRisk)
                .inconsistencyPenalty(inconsistencyScore)
                .layer3WarningPenalty(layer3WarningScore)
                .decayedPreviousRisk(decayedPreviousRisk)
                .riskLevel(riskLevel)
                .build();
    }

    /**
     * 위험 점수 간단 계산 (이전 점수 없이)
     */
    public double calculateSimpleRisk(OrthogonalSignals signals, InconsistencyResult inconsistency) {
        AccumulatedRiskResult result = calculateAccumulatedRisk(signals, inconsistency, 0.0);
        return result.getAccumulatedRisk();
    }

    // ===== Private Methods =====

    /**
     * 7차원 신호 가중 합산
     */
    private double calculateBaseRisk(OrthogonalSignals signals) {
        double[] signalValues = signals.toArray();
        double[] weights = {
                weightLayer1,    // Layer1
                weightLayer2,    // Layer2
                weightLayer3,    // Layer3
                weightLayer4,    // Layer4
                weightNetwork,   // Network
                weightCrypto,    // Crypto
                weightTiming     // Timing
        };

        double weightedSum = 0.0;
        for (int i = 0; i < signalValues.length && i < weights.length; i++) {
            weightedSum += signalValues[i] * weights[i];
        }

        return weightedSum;
    }

    /**
     * 위험 레벨 판정
     */
    private RiskLevel determineRiskLevel(double accumulatedRisk) {
        if (accumulatedRisk >= 0.85) {
            return RiskLevel.CRITICAL;
        } else if (accumulatedRisk >= 0.7) {
            return RiskLevel.HIGH;
        } else if (accumulatedRisk >= 0.5) {
            return RiskLevel.MEDIUM;
        } else if (accumulatedRisk >= 0.3) {
            return RiskLevel.LOW;
        } else {
            return RiskLevel.MINIMAL;
        }
    }

    // ===== Inner Classes =====

    /**
     * 누적 위험 결과
     */
    @Getter
    @Builder
    public static class AccumulatedRiskResult {
        private final double accumulatedRisk;       // 최종 누적 위험 (0.0~1.0)
        private final double baseRisk;              // 7-signal 기본 위험
        private final double inconsistencyPenalty;  // 불일치 패널티
        private final double layer3WarningPenalty;  // Layer3 경고 패널티
        private final double decayedPreviousRisk;   // 시간 감쇠된 이전 위험
        private final RiskLevel riskLevel;          // 위험 레벨
    }

    /**
     * 위험 레벨
     */
    public enum RiskLevel {
        MINIMAL,    // < 0.3
        LOW,        // 0.3 ~ 0.5
        MEDIUM,     // 0.5 ~ 0.7
        HIGH,       // 0.7 ~ 0.85
        CRITICAL    // >= 0.85
    }
}
