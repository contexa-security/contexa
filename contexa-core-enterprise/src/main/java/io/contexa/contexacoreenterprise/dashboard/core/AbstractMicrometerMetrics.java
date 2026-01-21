package io.contexa.contexacoreenterprise.dashboard.core;

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

@Slf4j
@RequiredArgsConstructor
public abstract class AbstractMicrometerMetrics implements DomainMetrics, EventRecorder {

    protected final MeterRegistry meterRegistry;
    private final String domain;

    @PostConstruct
    @Override
    public void initialize() {

        initializeCounters();
        initializeTimers();
        initializeGauges();

    }

    protected abstract void initializeCounters();

    protected abstract void initializeTimers();

    protected abstract void initializeGauges();

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        try {
            Counter counter = Counter.builder(domain + ".event")
                    .tag("type", eventType)
                    .description("Event count for " + eventType)
                    .register(meterRegistry);

            counter.increment();

            if (metadata != null && !metadata.isEmpty()) {
            }
        } catch (Exception e) {
            log.warn("[{}] Failed to record event: type={}", domain, eventType, e);
        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        try {
            Timer timer = Timer.builder(domain + ".operation.duration")
                    .tag("operation", operationName)
                    .description("Duration for " + operationName)
                    .register(meterRegistry);

            timer.record(durationNanos, TimeUnit.NANOSECONDS);

        } catch (Exception e) {
            log.warn("[{}] Failed to record duration: operation={}", domain, operationName, e);
        }
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("domain", domain);
        stats.put("metersCount", meterRegistry.getMeters().size());
        return stats;
    }

    @Override
    public void reset() {
    }

    protected Counter.Builder counterBuilder(String name, String description) {
        return Counter.builder(domain + "." + name)
                .description(description);
    }

    protected Timer.Builder timerBuilder(String name, String description) {
        return Timer.builder(domain + "." + name)
                .description(description);
    }
}
