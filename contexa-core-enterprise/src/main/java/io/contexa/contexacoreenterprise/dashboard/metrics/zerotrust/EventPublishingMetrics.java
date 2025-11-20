package io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust;

import io.contexa.contexacoreenterprise.dashboard.core.AbstractMicrometerMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 이벤트 발행 메트릭
 *
 * Zero Trust 시스템의 시작점인 이벤트 발행을 모니터링합니다.
 * 4개 발행 소스별로 메트릭을 수집하여 대시보드에서 가시화합니다.
 *
 * 발행 소스:
 * 1. Login (로그인 성공)
 * 2. @Protectable (메소드 인가 - AuthorizationManagerMethodInterceptor)
 * 3. URL Authorization (URL 인가 결정 - CustomDynamicAuthorizationManager)
 * 4. HTTP Filter (일반 HTTP 요청 - SecurityEventPublishingFilter)
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
@Component
public class EventPublishingMetrics extends AbstractMicrometerMetrics {

    // 이벤트 발행 소스별 카운터
    private Counter loginCounter;
    private Counter protectableCounter;
    private Counter urlAuthCounter;
    private Counter httpFilterCounter;

    // 이벤트 발행 지연 시간
    private Timer loginTimer;
    private Timer protectableTimer;
    private Timer urlAuthTimer;
    private Timer httpFilterTimer;

    // 이벤트 타입별 카운터
    private Counter authSuccessCounter;
    private Counter authFailureCounter;
    private Counter authzDecisionCounter;
    private Counter httpRequestCounter;

    // 샘플링 결정 카운터
    private Counter samplingPublishedCounter;
    private Counter samplingFilteredCounter;

    // 샘플링율 게이지
    private final AtomicLong totalSamplingDecisions = new AtomicLong(0);
    private final AtomicLong publishedDecisions = new AtomicLong(0);

    public EventPublishingMetrics(MeterRegistry meterRegistry) {
        super(meterRegistry, "zerotrust");
    }

    @Override
    protected void initializeCounters() {
        // 발행 소스별 카운터
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

        // 이벤트 타입별 카운터
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

        // 샘플링 결정 카운터
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

    // ===== Public API: 발행 소스별 기록 =====

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

    // ===== Public API: 이벤트 타입별 기록 =====

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

    // ===== Public API: 샘플링 결정 기록 =====

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
        // 샘플링율이 너무 낮거나 높으면 문제
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
