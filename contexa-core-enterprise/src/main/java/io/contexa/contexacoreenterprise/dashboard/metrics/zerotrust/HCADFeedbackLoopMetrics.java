package io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust;

import io.contexa.contexacommon.metrics.HCADFeedbackMetrics;
import io.contexa.contexacoreenterprise.dashboard.api.DomainMetrics;
import io.contexa.contexacoreenterprise.dashboard.api.EventRecorder;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class HCADFeedbackLoopMetrics implements HCADFeedbackMetrics, DomainMetrics, EventRecorder {

    private final MeterRegistry meterRegistry;

    private Counter analysisCounter;
    private Timer analysisTimer;

    private final AtomicLong layer1ThreatSearchSum = new AtomicLong(0);
    private final AtomicLong layer2BaselineSum = new AtomicLong(0);
    private final AtomicLong layer3AnomalySum = new AtomicLong(0);
    private final AtomicLong layer4CorrelationSum = new AtomicLong(0);
    private final AtomicLong contributionSampleCount = new AtomicLong(0);

    private Counter similarityVeryHigh; 
    private Counter similarityHigh;     
    private Counter similarityMedium;   
    private Counter similarityLow;      
    private Counter similarityVeryLow;  

    private Counter anomalyDetectedCounter;
    private Counter anomalyFalsePositiveCounter;

    private Counter baselineUpdatedCounter;
    private Counter thresholdAdjustedCounter;
    private Timer feedbackProcessingTimer;

    @PostConstruct
    public void init() {
        
        analysisCounter = Counter.builder("zerotrust.hcad.analysis.total")
            .description("HCAD 전체 분석 수행 횟수")
            .register(meterRegistry);

        analysisTimer = Timer.builder("zerotrust.hcad.analysis.duration")
            .description("HCAD 분석 소요 시간")
            .register(meterRegistry);

        meterRegistry.gauge("zerotrust.hcad.layer.threat_search.contribution", layer1ThreatSearchSum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        meterRegistry.gauge("zerotrust.hcad.layer.baseline.contribution", layer2BaselineSum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        meterRegistry.gauge("zerotrust.hcad.layer.anomaly.contribution", layer3AnomalySum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

        meterRegistry.gauge("zerotrust.hcad.layer.correlation.contribution", layer4CorrelationSum,
            sum -> contributionSampleCount.get() > 0 ? sum.get() / (double) contributionSampleCount.get() : 0.0);

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

        anomalyDetectedCounter = Counter.builder("zerotrust.hcad.anomaly.detected")
            .tag("type", "total")
            .description("이상 탐지 총 횟수")
            .register(meterRegistry);

        anomalyFalsePositiveCounter = Counter.builder("zerotrust.hcad.anomaly.detected")
            .tag("type", "false_positive")
            .description("오탐지 (False Positive) 횟수")
            .register(meterRegistry);

        baselineUpdatedCounter = Counter.builder("zerotrust.hcad.feedback.baseline.updated")
            .description("기준선 벡터 업데이트 횟수 (학습)")
            .register(meterRegistry);

        thresholdAdjustedCounter = Counter.builder("zerotrust.hcad.feedback.threshold.adjusted")
            .description("임계값 동적 조정 횟수 (학습)")
            .register(meterRegistry);

        feedbackProcessingTimer = Timer.builder("zerotrust.hcad.feedback.processing.duration")
            .description("피드백 처리 소요 시간")
            .register(meterRegistry);

            }

    public void recordAnalysis(long durationNanos, double finalSimilarity, boolean isAnomaly) {
        analysisCounter.increment();
        analysisTimer.record(durationNanos, TimeUnit.NANOSECONDS);

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

        if (isAnomaly) {
            anomalyDetectedCounter.increment();
        }
    }

    public void recordLayerContributions(
        double threatSearchContribution,
        double baselineContribution,
        double anomalyContribution,
        double correlationContribution
    ) {
        
        layer1ThreatSearchSum.addAndGet((long) (threatSearchContribution * 100));
        layer2BaselineSum.addAndGet((long) (baselineContribution * 100));
        layer3AnomalySum.addAndGet((long) (anomalyContribution * 100));
        layer4CorrelationSum.addAndGet((long) (correlationContribution * 100));
        contributionSampleCount.incrementAndGet();
    }

    public void recordFalsePositive() {
        anomalyFalsePositiveCounter.increment();
    }

    public void recordBaselineUpdate() {
        baselineUpdatedCounter.increment();
    }

    public void recordThresholdAdjustment() {
        thresholdAdjustedCounter.increment();
    }

    public void recordFeedbackProcessing(long durationNanos) {
        feedbackProcessingTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }

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

    @Override
    public double getHealthScore() {
        
        long totalAnomalies = (long) anomalyDetectedCounter.count();
        long falsePositives = (long) anomalyFalsePositiveCounter.count();

        double falsePositiveRate = totalAnomalies > 0 ?
            (double) falsePositives / totalAnomalies : 0.0;

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
