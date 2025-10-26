package io.contexa.contexacore.dashboard.metrics.zerotrust;

import io.contexa.contexacore.dashboard.api.DomainMetrics;
import io.contexa.contexacore.dashboard.api.EventRecorder;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HCAD 피드백 루프 메트릭 수집기
 *
 * 목적:
 * - HCAD 4-Layer 분석 각 레이어별 기여도 추적
 * - 피드백 루프 학습 효과 측정
 * - 유사도 계산 성능 모니터링
 *
 * 4-Layer 구조:
 * - Layer 1: RAG 위협 검색 (VectorStore 기반)
 * - Layer 2: 기준선 유사도 (Baseline Vector)
 * - Layer 3: 마할라노비스 이상도 (Mahalanobis Distance)
 * - Layer 4: 위협 상관관계 분석 (Threat Correlation)
 *
 * Prometheus 메트릭:
 * - zerotrust.hcad.analysis.total - 전체 분석 횟수
 * - zerotrust.hcad.analysis.duration - 분석 소요 시간
 * - zerotrust.hcad.layer.{layer}.contribution - 레이어별 기여도 (0.0-1.0)
 * - zerotrust.hcad.similarity.score - 최종 유사도 점수 분포
 * - zerotrust.hcad.anomaly.detected - 이상 탐지 횟수
 * - zerotrust.hcad.feedback.baseline.updated - 기준선 업데이트 횟수
 * - zerotrust.hcad.feedback.threshold.adjusted - 임계값 조정 횟수
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HCADFeedbackLoopMetrics implements DomainMetrics, EventRecorder {

    private final MeterRegistry meterRegistry;

    // 전체 분석 메트릭
    private Counter analysisCounter;
    private Timer analysisTimer;

    // 레이어별 기여도 추적 (AtomicLong으로 누적 합산)
    private final AtomicLong layer1ThreatSearchSum = new AtomicLong(0);
    private final AtomicLong layer2BaselineSum = new AtomicLong(0);
    private final AtomicLong layer3AnomalySum = new AtomicLong(0);
    private final AtomicLong layer4CorrelationSum = new AtomicLong(0);
    private final AtomicLong contributionSampleCount = new AtomicLong(0);

    // 유사도 점수 분포 (구간별 카운터)
    private Counter similarityVeryHigh; // 0.9-1.0
    private Counter similarityHigh;     // 0.7-0.9
    private Counter similarityMedium;   // 0.5-0.7
    private Counter similarityLow;      // 0.3-0.5
    private Counter similarityVeryLow;  // 0.0-0.3

    // 이상 탐지
    private Counter anomalyDetectedCounter;
    private Counter anomalyFalsePositiveCounter;

    // 피드백 루프 학습
    private Counter baselineUpdatedCounter;
    private Counter thresholdAdjustedCounter;
    private Timer feedbackProcessingTimer;

    @PostConstruct
    public void init() {
        // 전체 분석 메트릭
        analysisCounter = Counter.builder("zerotrust.hcad.analysis.total")
            .description("HCAD 전체 분석 수행 횟수")
            .register(meterRegistry);

        analysisTimer = Timer.builder("zerotrust.hcad.analysis.duration")
            .description("HCAD 분석 소요 시간")
            .register(meterRegistry);

        // 레이어별 평균 기여도 게이지
        meterRegistry.gauge("zerotrust.hcad.layer.threat_search.contribution", layer1ThreatSearchSum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        meterRegistry.gauge("zerotrust.hcad.layer.baseline.contribution", layer2BaselineSum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        meterRegistry.gauge("zerotrust.hcad.layer.anomaly.contribution", layer3AnomalySum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        meterRegistry.gauge("zerotrust.hcad.layer.correlation.contribution", layer4CorrelationSum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        // 유사도 점수 분포
        similarityVeryHigh = Counter.builder("zerotrust.hcad.similarity.score")
            .tag("range", "very_high")
            .tag("min", "0.9")
            .tag("max", "1.0")
            .description("유사도 매우 높음 (0.9-1.0)")
            .register(meterRegistry);

        similarityHigh = Counter.builder("zerotrust.hcad.similarity.score")
            .tag("range", "high")
            .tag("min", "0.7")
            .tag("max", "0.9")
            .description("유사도 높음 (0.7-0.9) - HOT Path 경계")
            .register(meterRegistry);

        similarityMedium = Counter.builder("zerotrust.hcad.similarity.score")
            .tag("range", "medium")
            .tag("min", "0.5")
            .tag("max", "0.7")
            .description("유사도 중간 (0.5-0.7)")
            .register(meterRegistry);

        similarityLow = Counter.builder("zerotrust.hcad.similarity.score")
            .tag("range", "low")
            .tag("min", "0.3")
            .tag("max", "0.5")
            .description("유사도 낮음 (0.3-0.5)")
            .register(meterRegistry);

        similarityVeryLow = Counter.builder("zerotrust.hcad.similarity.score")
            .tag("range", "very_low")
            .tag("min", "0.0")
            .tag("max", "0.3")
            .description("유사도 매우 낮음 (0.0-0.3)")
            .register(meterRegistry);

        // 이상 탐지
        anomalyDetectedCounter = Counter.builder("zerotrust.hcad.anomaly.detected")
            .tag("type", "total")
            .description("이상 탐지 총 횟수")
            .register(meterRegistry);

        anomalyFalsePositiveCounter = Counter.builder("zerotrust.hcad.anomaly.detected")
            .tag("type", "false_positive")
            .description("오탐지 (False Positive) 횟수")
            .register(meterRegistry);

        // 피드백 루프
        baselineUpdatedCounter = Counter.builder("zerotrust.hcad.feedback.baseline.updated")
            .description("기준선 벡터 업데이트 횟수 (학습)")
            .register(meterRegistry);

        thresholdAdjustedCounter = Counter.builder("zerotrust.hcad.feedback.threshold.adjusted")
            .description("임계값 동적 조정 횟수 (학습)")
            .register(meterRegistry);

        feedbackProcessingTimer = Timer.builder("zerotrust.hcad.feedback.processing.duration")
            .description("피드백 처리 소요 시간")
            .register(meterRegistry);

        log.info("[HCADFeedbackLoopMetrics] 초기화 완료 - 4-Layer 기여도 추적 시작");
    }

    /**
     * HCAD 분석 수행 기록
     *
     * @param durationNanos 분석 소요 시간 (나노초)
     * @param finalSimilarity 최종 유사도 점수 (0.0-1.0)
     * @param isAnomaly 이상 탐지 여부
     */
    public void recordAnalysis(long durationNanos, double finalSimilarity, boolean isAnomaly) {
        analysisCounter.increment();
        analysisTimer.record(durationNanos, TimeUnit.NANOSECONDS);

        // 유사도 점수 분포 기록
        if (finalSimilarity >= 0.9) {
            similarityVeryHigh.increment();
        } else if (finalSimilarity >= 0.7) {
            similarityHigh.increment();
        } else if (finalSimilarity >= 0.5) {
            similarityMedium.increment();
        } else if (finalSimilarity >= 0.3) {
            similarityLow.increment();
        } else {
            similarityVeryLow.increment();
        }

        // 이상 탐지 기록
        if (isAnomaly) {
            anomalyDetectedCounter.increment();
        }
    }

    /**
     * 4-Layer 기여도 기록
     *
     * 각 레이어가 최종 유사도에 기여한 정도를 추적
     *
     * @param threatSearchContribution Layer 1 기여도 (0.0-1.0)
     * @param baselineContribution Layer 2 기여도 (0.0-1.0)
     * @param anomalyContribution Layer 3 기여도 (0.0-1.0)
     * @param correlationContribution Layer 4 기여도 (0.0-1.0)
     */
    public void recordLayerContributions(
        double threatSearchContribution,
        double baselineContribution,
        double anomalyContribution,
        double correlationContribution
    ) {
        // 기여도를 0-100 스케일로 변환하여 저장 (평균 계산 용이)
        layer1ThreatSearchSum.addAndGet((long) (threatSearchContribution * 100));
        layer2BaselineSum.addAndGet((long) (baselineContribution * 100));
        layer3AnomalySum.addAndGet((long) (anomalyContribution * 100));
        layer4CorrelationSum.addAndGet((long) (correlationContribution * 100));
        contributionSampleCount.incrementAndGet();
    }

    /**
     * 오탐지 (False Positive) 기록
     *
     * 이상으로 판정했으나 실제로는 정상인 경우
     */
    public void recordFalsePositive() {
        anomalyFalsePositiveCounter.increment();
    }

    /**
     * 기준선 업데이트 기록
     *
     * 피드백 루프를 통해 BaselineVector가 학습된 경우
     */
    public void recordBaselineUpdate() {
        baselineUpdatedCounter.increment();
    }

    /**
     * 임계값 조정 기록
     *
     * 피드백 루프를 통해 임계값이 동적으로 조정된 경우
     */
    public void recordThresholdAdjustment() {
        thresholdAdjustedCounter.increment();
    }

    /**
     * 피드백 처리 시간 기록
     *
     * @param durationNanos 피드백 처리 소요 시간 (나노초)
     */
    public void recordFeedbackProcessing(long durationNanos) {
        feedbackProcessingTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }

    // ===== MetricsCollector 인터페이스 구현 =====

    @Override
    public String getDomain() {
        return "zerotrust.hcad";
    }

    @Override
    public void initialize() {
        init();
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_analyses", analysisCounter.count());
        stats.put("total_anomalies", anomalyDetectedCounter.count());
        stats.put("false_positives", anomalyFalsePositiveCounter.count());
        stats.put("baseline_updates", baselineUpdatedCounter.count());
        stats.put("threshold_adjustments", thresholdAdjustedCounter.count());
        stats.put("avg_layer1_contribution", contributionSampleCount.get() > 0 ?
            layer1ThreatSearchSum.get() / (double) contributionSampleCount.get() / 100.0 : 0.0);
        stats.put("avg_layer2_contribution", contributionSampleCount.get() > 0 ?
            layer2BaselineSum.get() / (double) contributionSampleCount.get() / 100.0 : 0.0);
        stats.put("avg_layer3_contribution", contributionSampleCount.get() > 0 ?
            layer3AnomalySum.get() / (double) contributionSampleCount.get() / 100.0 : 0.0);
        stats.put("avg_layer4_contribution", contributionSampleCount.get() > 0 ?
            layer4CorrelationSum.get() / (double) contributionSampleCount.get() / 100.0 : 0.0);
        return stats;
    }

    @Override
    public void reset() {
        layer1ThreatSearchSum.set(0);
        layer2BaselineSum.set(0);
        layer3AnomalySum.set(0);
        layer4CorrelationSum.set(0);
        contributionSampleCount.set(0);
    }

    // ===== DomainMetrics 인터페이스 구현 =====

    @Override
    public double getHealthScore() {
        // 건강도 = (1 - 오탐율) * 레이어 균형도
        long totalAnomalies = (long) anomalyDetectedCounter.count();
        long falsePositives = (long) anomalyFalsePositiveCounter.count();

        double falsePositiveRate = totalAnomalies > 0 ?
            (double) falsePositives / totalAnomalies : 0.0;

        // 레이어 기여도 균형 (표준편차가 낮을수록 좋음)
        double[] contributions = {
            contributionSampleCount.get() > 0 ? layer1ThreatSearchSum.get() / (double) contributionSampleCount.get() / 100.0 : 0.25,
            contributionSampleCount.get() > 0 ? layer2BaselineSum.get() / (double) contributionSampleCount.get() / 100.0 : 0.25,
            contributionSampleCount.get() > 0 ? layer3AnomalySum.get() / (double) contributionSampleCount.get() / 100.0 : 0.25,
            contributionSampleCount.get() > 0 ? layer4CorrelationSum.get() / (double) contributionSampleCount.get() / 100.0 : 0.25
        };

        double mean = (contributions[0] + contributions[1] + contributions[2] + contributions[3]) / 4.0;
        double variance = 0;
        for (double c : contributions) {
            variance += Math.pow(c - mean, 2);
        }
        variance /= 4.0;
        double stdDev = Math.sqrt(variance);

        // 균형도 점수 (표준편차가 0.1 이하면 완벽, 0.3 이상이면 불균형)
        double balanceScore = Math.max(0, 1.0 - (stdDev / 0.3));

        return (1.0 - falsePositiveRate) * balanceScore;
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("analysis_count", (double) analysisCounter.count());
        metrics.put("anomaly_rate", analysisCounter.count() > 0 ?
            anomalyDetectedCounter.count() / analysisCounter.count() : 0.0);
        metrics.put("false_positive_rate", anomalyDetectedCounter.count() > 0 ?
            anomalyFalsePositiveCounter.count() / anomalyDetectedCounter.count() : 0.0);
        metrics.put("learning_rate", (double) (baselineUpdatedCounter.count() + thresholdAdjustedCounter.count()));
        metrics.put("health_score", getHealthScore());
        return metrics;
    }

    // ===== EventRecorder 인터페이스 구현 =====

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        switch (eventType) {
            case "analysis":
                long duration = metadata.containsKey("duration") ?
                    ((Number) metadata.get("duration")).longValue() : 0L;
                double similarity = metadata.containsKey("similarity") ?
                    ((Number) metadata.get("similarity")).doubleValue() : 0.0;
                boolean isAnomaly = metadata.containsKey("isAnomaly") ?
                    (Boolean) metadata.get("isAnomaly") : false;
                recordAnalysis(duration, similarity, isAnomaly);
                break;
            case "false_positive":
                recordFalsePositive();
                break;
            case "baseline_update":
                recordBaselineUpdate();
                break;
            case "threshold_adjustment":
                recordThresholdAdjustment();
                break;
            default:
                log.warn("Unknown event type: {}", eventType);
        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        if ("analysis".equals(operationName)) {
            analysisTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        } else if ("feedback_processing".equals(operationName)) {
            feedbackProcessingTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        }
    }
}
