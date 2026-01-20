package io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust;

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
public class EventPublishingMetrics extends AbstractMicrometerMetrics {

    
    private Counter loginCounter;
    private Counter protectableCounter;
    private Counter urlAuthCounter;
    private Counter httpFilterCounter;

    
    private Timer loginTimer;
    private Timer protectableTimer;
    private Timer urlAuthTimer;
    private Timer httpFilterTimer;

    
    private Counter authSuccessCounter;
    private Counter authFailureCounter;
    private Counter authzDecisionCounter;
    private Counter httpRequestCounter;

    
    private Counter samplingPublishedCounter;
    private Counter samplingFilteredCounter;

    
    private final AtomicLong totalSamplingDecisions = new AtomicLong(0);
    private final AtomicLong publishedDecisions = new AtomicLong(0);

    public EventPublishingMetrics(MeterRegistry meterRegistry) {
        super(meterRegistry, "zerotrust");
    }

    @Override
    protected void initializeCounters() {
        
        loginCounter = counterBuilder("event.published", "Events published by Login")
                .tag("source", "login")
                .register(meterRegistry);

        protectableCounter = counterBuilder("event.published", "Events published by @Protectable")
                .tag("source", "protectable")
                .register(meterRegistry);

        urlAuthCounter = counterBuilder("event.published", "Events published by URL Authorization")
                .tag("source", "url_auth")
                .register(meterRegistry);

        httpFilterCounter = counterBuilder("event.published", "Events published by HTTP Filter")
                .tag("source", "http_filter")
                .register(meterRegistry);

        
        authSuccessCounter = counterBuilder("event.type", "Authentication success events")
                .tag("type", "auth_success")
                .register(meterRegistry);

        authFailureCounter = counterBuilder("event.type", "Authentication failure events")
                .tag("type", "auth_failure")
                .register(meterRegistry);

        authzDecisionCounter = counterBuilder("event.type", "Authorization decision events")
                .tag("type", "authz_decision")
                .register(meterRegistry);

        httpRequestCounter = counterBuilder("event.type", "HTTP request events")
                .tag("type", "http_request")
                .register(meterRegistry);

        
        samplingPublishedCounter = counterBuilder("event.sampling.decision", "Events published")
                .tag("decision", "published")
                .register(meterRegistry);

        samplingFilteredCounter = counterBuilder("event.sampling.decision", "Events filtered")
                .tag("decision", "filtered")
                .register(meterRegistry);
    }

    @Override
    protected void initializeTimers() {
        loginTimer = timerBuilder("event.publish.duration", "Login publishing latency")
                .tag("source", "login")
                .register(meterRegistry);

        protectableTimer = timerBuilder("event.publish.duration", "@Protectable publishing latency")
                .tag("source", "protectable")
                .register(meterRegistry);

        urlAuthTimer = timerBuilder("event.publish.duration", "URL Authorization publishing latency")
                .tag("source", "url_auth")
                .register(meterRegistry);

        httpFilterTimer = timerBuilder("event.publish.duration", "HTTP Filter publishing latency")
                .tag("source", "http_filter")
                .register(meterRegistry);
    }

    @Override
    protected void initializeGauges() {
        meterRegistry.gauge("zerotrust.event.sampling.rate", this, metrics -> {
            long total = metrics.totalSamplingDecisions.get();
            long published = metrics.publishedDecisions.get();
            return total > 0 ? (double) published / total : 0.0;
        });
    }

    

    public void recordLogin(long durationNanos) {
        loginCounter.increment();
        loginTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }

    public void recordProtectable(long durationNanos) {
        protectableCounter.increment();
        protectableTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }

    public void recordUrlAuth(long durationNanos) {
        urlAuthCounter.increment();
        urlAuthTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }

    public void recordHttpFilter(long durationNanos) {
        httpFilterCounter.increment();
        httpFilterTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }

    

    public void recordAuthSuccess() {
        authSuccessCounter.increment();
    }

    public void recordAuthFailure() {
        authFailureCounter.increment();
    }

    public void recordAuthzDecision() {
        authzDecisionCounter.increment();
    }

    public void recordHttpRequest() {
        httpRequestCounter.increment();
    }

    

    public void recordSamplingDecision(boolean shouldPublish) {
        totalSamplingDecisions.incrementAndGet();

        if (shouldPublish) {
            samplingPublishedCounter.increment();
            publishedDecisions.incrementAndGet();
        } else {
            samplingFilteredCounter.increment();
        }
    }

    public double getCurrentSamplingRate() {
        long total = totalSamplingDecisions.get();
        long published = publishedDecisions.get();
        return total > 0 ? (double) published / total : 0.0;
    }

    @Override
    public double getHealthScore() {
        
        double samplingRate = getCurrentSamplingRate();
        if (samplingRate < 0.1 || samplingRate > 0.9) {
            return 0.7;
        }
        return 1.0;
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("samplingRate", getCurrentSamplingRate());
        metrics.put("loginCount", loginCounter.count());
        metrics.put("httpFilterCount", httpFilterCounter.count());
        metrics.put("authSuccessCount", authSuccessCounter.count());
        metrics.put("authFailureCount", authFailureCounter.count());
        return metrics;
    }
}
