package io.contexa.contexacommon.metrics;

/**
 * HCAD Feedback Metrics Interface
 *
 * <p>
 * Core와 Enterprise 사이의 HCAD 피드백 메트릭 인터페이스입니다.
 * Enterprise가 있으면 실제 메트릭이 수집되고, 없으면 아무 동작 안 함.
 * </p>
 *
 * @since 0.1.1
 */
public interface HCADFeedbackMetrics {

    /**
     * HCAD 분석 수행 기록
     *
     * @param durationNanos 분석 소요 시간 (나노초)
     * @param finalSimilarity 최종 유사도 점수 (0.0-1.0)
     * @param isAnomaly 이상 탐지 여부
     */
    void recordAnalysis(long durationNanos, double finalSimilarity, boolean isAnomaly);

    /**
     * 4-Layer 기여도 기록
     *
     * @param threatSearchContribution Layer 1 기여도 (0.0-1.0)
     * @param baselineContribution Layer 2 기여도 (0.0-1.0)
     * @param anomalyContribution Layer 3 기여도 (0.0-1.0)
     * @param correlationContribution Layer 4 기여도 (0.0-1.0)
     */
    void recordLayerContributions(
        double threatSearchContribution,
        double baselineContribution,
        double anomalyContribution,
        double correlationContribution
    );

    /**
     * 기준선 업데이트 기록
     */
    void recordBaselineUpdate();

    /**
     * 임계값 조정 기록
     */
    void recordThresholdAdjustment();

    /**
     * 피드백 처리 시간 기록
     *
     * @param durationNanos 피드백 처리 소요 시간 (나노초)
     */
    void recordFeedbackProcessing(long durationNanos);
}
