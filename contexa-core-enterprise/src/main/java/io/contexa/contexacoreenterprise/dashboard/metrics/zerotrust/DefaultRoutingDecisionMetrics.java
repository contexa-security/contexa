package io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust;

import io.contexa.contexacore.autonomous.metrics.RoutingDecisionMetrics;
import io.contexa.contexacoreenterprise.dashboard.core.AbstractMicrometerMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Routing Decision 메트릭 구현체
 *
 * Hot/Cold Path 라우팅 결정 및 Processing Mode별 통계 수집
 *
 * Hot/Cold Path 기준:
 * - Hot Path: 유사도 > 0.70 (빠른 처리, PASS_THROUGH)
 * - Cold Path: 유사도 <= 0.70 (AI 분석, AI_ANALYSIS)
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
public class DefaultRoutingDecisionMetrics extends AbstractMicrometerMetrics implements RoutingDecisionMetrics {

    // 라우팅 경로 카운터
    private Counter hotPathCounter;
    private Counter coldPathCounter;

    // Processing Mode별 카운터
    private Counter passThroughCounter;
    private Counter aiAnalysisCounter;
    private Counter realtimeBlockCounter;
    private Counter soarOrchestrationCounter;
    private Counter awaitApprovalCounter;

    // 유사도 분포 카운터
    private Counter similarityVeryHigh;
    private Counter similarityHigh;
    private Counter similarityMedium;
    private Counter similarityLow;
    private Counter similarityVeryLow;

    // 라우팅 결정 시간
    private Timer routingDecisionTimer;

    // Hot Path 비율 계산용
    private final AtomicLong hotPathCount = new AtomicLong(0);
    private final AtomicLong totalRoutingCount = new AtomicLong(0);

    public DefaultRoutingDecisionMetrics(MeterRegistry meterRegistry) {
        super(meterRegistry, "zerotrust");
    }

    @Override
    protected void initializeCounters() {
        // 라우팅 경로 카운터
        hotPathCounter = counterBuilder("routing.decision", "Hot Path 라우팅 횟수")
                .tag("path", "hot")
                .register(meterRegistry);

        coldPathCounter = counterBuilder("routing.decision", "Cold Path 라우팅 횟수")
                .tag("path", "cold")
                .register(meterRegistry);

        // Processing Mode별 카운터
        passThroughCounter = counterBuilder("routing.mode", "PASS_THROUGH 모드")
                .tag("mode", "pass_through")
                .register(meterRegistry);

        aiAnalysisCounter = counterBuilder("routing.mode", "AI_ANALYSIS 모드")
                .tag("mode", "ai_analysis")
                .register(meterRegistry);

        realtimeBlockCounter = counterBuilder("routing.mode", "REALTIME_BLOCK 모드")
                .tag("mode", "realtime_block")
                .register(meterRegistry);

        soarOrchestrationCounter = counterBuilder("routing.mode", "SOAR_ORCHESTRATION 모드")
                .tag("mode", "soar_orchestration")
                .register(meterRegistry);

        awaitApprovalCounter = counterBuilder("routing.mode", "AWAIT_APPROVAL 모드")
                .tag("mode", "await_approval")
                .register(meterRegistry);

        // 유사도 분포 카운터
        similarityVeryHigh = counterBuilder("routing.similarity.distribution", "유사도 매우 높음 (0.9-1.0)")
                .tag("range", "very_high")
                .tag("min", "0.9")
                .tag("max", "1.0")
                .register(meterRegistry);

        similarityHigh = counterBuilder("routing.similarity.distribution", "유사도 높음 (0.7-0.9)")
                .tag("range", "high")
                .tag("min", "0.7")
                .tag("max", "0.9")
                .register(meterRegistry);

        similarityMedium = counterBuilder("routing.similarity.distribution", "유사도 중간 (0.5-0.7)")
                .tag("range", "medium")
                .tag("min", "0.5")
                .tag("max", "0.7")
                .register(meterRegistry);

        similarityLow = counterBuilder("routing.similarity.distribution", "유사도 낮음 (0.3-0.5)")
                .tag("range", "low")
                .tag("min", "0.3")
                .tag("max", "0.5")
                .register(meterRegistry);

        similarityVeryLow = counterBuilder("routing.similarity.distribution", "유사도 매우 낮음 (0.0-0.3)")
                .tag("range", "very_low")
                .tag("min", "0.0")
                .tag("max", "0.3")
                .register(meterRegistry);
    }

    @Override
    protected void initializeTimers() {
        routingDecisionTimer = timerBuilder("routing.decision.duration", "라우팅 결정 소요 시간")
                .register(meterRegistry);
    }

    @Override
    protected void initializeGauges() {
        meterRegistry.gauge("zerotrust.routing.hot.ratio", hotPathCount,
                count -> totalRoutingCount.get() > 0 ? (count.get() / (double) totalRoutingCount.get()) * 100.0 : 0.0);
    }

    // ===== Public API =====

    /**
     * Hot Path 라우팅 기록
     */
    @Override
    public void recordHotPath(long durationNanos, double similarityScore, String processingMode) {
        hotPathCounter.increment();
        hotPathCount.incrementAndGet();
        totalRoutingCount.incrementAndGet();

        routingDecisionTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        recordSimilarityDistribution(similarityScore);
        recordProcessingMode(processingMode);
    }

    /**
     * Cold Path 라우팅 기록
     */
    @Override
    public void recordColdPath(long durationNanos, double similarityScore, String processingMode) {
        coldPathCounter.increment();
        totalRoutingCount.incrementAndGet();

        routingDecisionTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        recordSimilarityDistribution(similarityScore);
        recordProcessingMode(processingMode);
    }

    private void recordSimilarityDistribution(double similarityScore) {
        if (similarityScore >= 0.9) {
            similarityVeryHigh.increment();
        } else if (similarityScore >= 0.7) {
            similarityHigh.increment();
        } else if (similarityScore >= 0.5) {
            similarityMedium.increment();
        } else if (similarityScore >= 0.3) {
            similarityLow.increment();
        } else {
            similarityVeryLow.increment();
        }
    }

    private void recordProcessingMode(String processingMode) {
        if (processingMode == null) {
            return;
        }

        switch (processingMode.toUpperCase()) {
            case "PASS_THROUGH":
                passThroughCounter.increment();
                break;
            case "AI_ANALYSIS":
                aiAnalysisCounter.increment();
                break;
            case "REALTIME_BLOCK":
                realtimeBlockCounter.increment();
                break;
            case "SOAR_ORCHESTRATION":
                soarOrchestrationCounter.increment();
                break;
            case "AWAIT_APPROVAL":
                awaitApprovalCounter.increment();
                break;
            default:
                log.debug("알 수 없는 Processing Mode: {}", processingMode);
        }
    }

    public double getHotPathRatio() {
        long total = totalRoutingCount.get();
        long hot = hotPathCount.get();
        return total > 0 ? (hot / (double) total) * 100.0 : 0.0;
    }

    @Override
    public double getHealthScore() {
        // Hot Path 비율이 적절한지 확인 (50-90% 권장)
        double hotRatio = getHotPathRatio();
        if (hotRatio < 50.0 || hotRatio > 90.0) {
            return 0.8;
        }
        return 1.0;
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("hotPathRatio", getHotPathRatio());
        metrics.put("hotPathCount", (double) hotPathCount.get());
        metrics.put("coldPathCount", (double) (totalRoutingCount.get() - hotPathCount.get()));
        metrics.put("totalRoutingCount", (double) totalRoutingCount.get());
        return metrics;
    }
}
