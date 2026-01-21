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

@Slf4j
public class DefaultRoutingDecisionMetrics extends AbstractMicrometerMetrics implements RoutingDecisionMetrics {

    private Counter hotPathCounter;
    private Counter coldPathCounter;

    private Counter passThroughCounter;
    private Counter aiAnalysisCounter;
    private Counter realtimeBlockCounter;
    private Counter soarOrchestrationCounter;
    private Counter awaitApprovalCounter;

    private Timer routingDecisionTimer;

    private final AtomicLong hotPathCount = new AtomicLong(0);
    private final AtomicLong totalRoutingCount = new AtomicLong(0);

    public DefaultRoutingDecisionMetrics(MeterRegistry meterRegistry) {
        super(meterRegistry, "zerotrust");
    }

    @Override
    protected void initializeCounters() {
        
        hotPathCounter = counterBuilder("routing.decision", "Hot Path 라우팅 횟수")
                .tag("path", "hot")
                .register(meterRegistry);

        coldPathCounter = counterBuilder("routing.decision", "Cold Path 라우팅 횟수")
                .tag("path", "cold")
                .register(meterRegistry);

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

    @Override
    public void recordHotPath(long durationNanos, String processingMode) {
        hotPathCounter.increment();
        hotPathCount.incrementAndGet();
        totalRoutingCount.incrementAndGet();

        routingDecisionTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        recordProcessingMode(processingMode);
    }

    @Override
    public void recordColdPath(long durationNanos, String processingMode) {
        coldPathCounter.increment();
        totalRoutingCount.incrementAndGet();

        routingDecisionTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        recordProcessingMode(processingMode);
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
                        }
    }

    public double getHotPathRatio() {
        long total = totalRoutingCount.get();
        long hot = hotPathCount.get();
        return total > 0 ? (hot / (double) total) * 100.0 : 0.0;
    }

    @Override
    public double getHealthScore() {
        
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
