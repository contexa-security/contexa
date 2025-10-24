package io.contexa.contexacore.autonomous.event.decision;

/**
 * Event Tier (통합)
 *
 * 익명 사용자 + 인증 사용자 통합 위험도 등급
 *
 * 핵심 설계 원칙:
 * 1. Risk Score 기반 (HCAD 직접 사용 X)
 * 2. 익명 사용자: (1.0 - HCAD) * 0.7 + ipThreat * 0.3
 * 3. 인증 사용자: (1.0 - HCAD) * 0.5 + (1.0 - trustScore) * 0.5
 * 4. Hot Path도 10% 샘플링 (정상 패턴 학습용)
 *
 * Tier 분류:
 * - CRITICAL: Risk > 0.8 (매우 위험)
 * - HIGH: Risk 0.6~0.8 (위험)
 * - MEDIUM: Risk 0.4~0.6 (보통)
 * - LOW: Risk 0.2~0.4 (낮음)
 * - BENIGN: Risk < 0.2 (정상)
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
public enum EventTier {

    /**
     * 매우 위험 (Risk > 0.8)
     * - 100% 즉시 발행
     * - 명확한 공격 패턴 또는 매우 의심스러운 행동
     * - SQL Injection, 계정 탈취 시도 등
     */
    CRITICAL(0.8, 1.0, 1.0, true),

    /**
     * 위험 (Risk 0.6~0.8)
     * - 80% 샘플링 (시스템 상태에 따라 조정)
     * - 의심스러운 행동 패턴
     */
    HIGH(0.6, 0.8, 0.8, false),

    /**
     * 보통 (Risk 0.4~0.6)
     * - 50% 샘플링
     * - 중간 수준의 위험도
     */
    MEDIUM(0.4, 0.6, 0.5, false),

    /**
     * 낮음 (Risk 0.2~0.4)
     * - 20% 샘플링
     * - 비교적 정상에 가까운 행동
     */
    LOW(0.2, 0.4, 0.2, false),

    /**
     * 정상 (Risk < 0.2)
     * - 10% 샘플링 (Hot Path 정상 패턴 학습용)
     * - 정상 사용자 행동과 매우 유사
     * - 핵심 수정: 0% → 10% (피드백 루프 연결)
     */
    BENIGN(0.0, 0.2, 0.1, false);

    private final double minRisk;
    private final double maxRisk;
    private final double baseSamplingRate;
    private final boolean immediatePublishing;

    EventTier(double minRisk, double maxRisk, double baseSamplingRate, boolean immediatePublishing) {
        this.minRisk = minRisk;
        this.maxRisk = maxRisk;
        this.baseSamplingRate = baseSamplingRate;
        this.immediatePublishing = immediatePublishing;
    }

    /**
     * Risk Score 기반 Tier 분류
     *
     * @param riskScore 위험도 점수 (0.0 ~ 1.0)
     * @return 분류된 Tier
     */
    public static EventTier fromRiskScore(Double riskScore) {
        // Risk Score가 없으면 CRITICAL (안전한 쪽으로 Fail-Safe)
        if (riskScore == null) {
            return CRITICAL;
        }

        // Risk Score 범위 보정
        double risk = Math.max(0.0, Math.min(1.0, riskScore));

        // Tier 분류 (Risk Score 기준)
        if (risk > 0.8) {
            return CRITICAL;
        } else if (risk > 0.6) {
            return HIGH;
        } else if (risk > 0.4) {
            return MEDIUM;
        } else if (risk > 0.2) {
            return LOW;
        } else {
            return BENIGN;
        }
    }

    /**
     * 즉시 발행 여부
     *
     * @return true면 샘플링 없이 100% 발행
     */
    public boolean requiresImmediatePublishing() {
        return immediatePublishing;
    }

    /**
     * 기본 샘플링 비율
     *
     * @return 기본 샘플링 비율 (0.0 ~ 1.0)
     */
    public double getBaseSamplingRate() {
        return baseSamplingRate;
    }

    /**
     * Risk 최소값
     */
    public double getMinRisk() {
        return minRisk;
    }

    /**
     * Risk 최대값
     */
    public double getMaxRisk() {
        return maxRisk;
    }

    /**
     * Tier 상향 조정 (추가 위협 신호 발견 시)
     *
     * @return 한 단계 높은 Tier (CRITICAL이면 그대로)
     */
    public EventTier escalate() {
        return switch (this) {
            case BENIGN -> LOW;
            case LOW -> MEDIUM;
            case MEDIUM -> HIGH;
            case HIGH -> CRITICAL;
            case CRITICAL -> CRITICAL;  // 최고 등급은 그대로
        };
    }

    @Override
    public String toString() {
        return String.format("%s(Risk: %.2f~%.2f, 샘플링: %.0f%%)",
                name(), minRisk, maxRisk, baseSamplingRate * 100);
    }
}
