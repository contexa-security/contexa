package io.contexa.contexacore.autonomous.event.backpressure;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class BackpressureManager {

    private final MeterRegistry meterRegistry;
    private final CircuitBreakerRegistry circuitBreakerRegistry;

    @Value("${security.backpressure.max-concurrent-requests:100}")
    private int maxConcurrentRequests;

    @Value("${security.backpressure.timeout-ms:5000}")
    private long timeoutMs;

    @Value("${security.backpressure.circuit-breaker.failure-rate:50}")
    private float circuitBreakerFailureRate;

    @Value("${security.backpressure.circuit-breaker.wait-duration-open:60}")
    private int circuitBreakerWaitDurationOpen;

    private Semaphore requestSemaphore;

    private CircuitBreaker kafkaCircuitBreaker;
    private CircuitBreaker redisCircuitBreaker;
    private CircuitBreaker aiCircuitBreaker;

    private final AtomicInteger activeRequests = new AtomicInteger(0);
    private final AtomicLong rejectedRequests = new AtomicLong(0);
    private final AtomicLong timeoutRequests = new AtomicLong(0);

    public BackpressureManager(MeterRegistry meterRegistry, CircuitBreakerRegistry circuitBreakerRegistry) {
        this.meterRegistry = meterRegistry;
        this.circuitBreakerRegistry = circuitBreakerRegistry;
    }

    @PostConstruct
    public void initialize() {
        
        requestSemaphore = new Semaphore(maxConcurrentRequests);

        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
            .failureRateThreshold(circuitBreakerFailureRate)
            .waitDurationInOpenState(Duration.ofSeconds(circuitBreakerWaitDurationOpen))
            .slidingWindowSize(100)
            .minimumNumberOfCalls(10)
            .permittedNumberOfCallsInHalfOpenState(5)
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .build();

        kafkaCircuitBreaker = circuitBreakerRegistry.circuitBreaker("kafka", config);
        redisCircuitBreaker = circuitBreakerRegistry.circuitBreaker("redis", config);
        aiCircuitBreaker = circuitBreakerRegistry.circuitBreaker("ai-inference", config);

        Gauge.builder("backpressure.active.requests", activeRequests, AtomicInteger::get)
            .description("Number of active concurrent requests")
            .register(meterRegistry);

        Gauge.builder("backpressure.rejected.requests", rejectedRequests, AtomicLong::get)
            .description("Number of rejected requests due to backpressure")
            .register(meterRegistry);

        Gauge.builder("backpressure.timeout.requests", timeoutRequests, AtomicLong::get)
            .description("Number of requests that timed out")
            .register(meterRegistry);

        Gauge.builder("backpressure.available.permits", requestSemaphore, Semaphore::availablePermits)
            .description("Number of available request permits")
            .register(meterRegistry);

            }

    public boolean tryAcquire() {
        try {
            boolean acquired = requestSemaphore.tryAcquire(timeoutMs, TimeUnit.MILLISECONDS);
            if (acquired) {
                activeRequests.incrementAndGet();
                                return true;
            } else {
                rejectedRequests.incrementAndGet();
                log.warn("Request REJECTED due to backpressure: active={}, max={}",
                    activeRequests.get(), maxConcurrentRequests);
                return false;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            timeoutRequests.incrementAndGet();
            log.error("Request timeout during backpressure check", e);
            return false;
        }
    }

    public void release() {
        requestSemaphore.release();
        activeRequests.decrementAndGet();
            }

    public boolean isKafkaAvailable() {
        CircuitBreaker.State state = kafkaCircuitBreaker.getState();
        boolean available = state == CircuitBreaker.State.CLOSED || state == CircuitBreaker.State.HALF_OPEN;

        if (!available) {
            log.warn("Kafka circuit breaker is OPEN: state={}", state);
        }

        return available;
    }

    public boolean isRedisAvailable() {
        CircuitBreaker.State state = redisCircuitBreaker.getState();
        boolean available = state == CircuitBreaker.State.CLOSED || state == CircuitBreaker.State.HALF_OPEN;

        if (!available) {
            log.warn("Redis circuit breaker is OPEN: state={}", state);
        }

        return available;
    }

    public boolean isAIAvailable() {
        CircuitBreaker.State state = aiCircuitBreaker.getState();
        boolean available = state == CircuitBreaker.State.CLOSED || state == CircuitBreaker.State.HALF_OPEN;

        if (!available) {
            log.warn("AI inference circuit breaker is OPEN: state={}", state);
        }

        return available;
    }

    public void recordKafkaSuccess() {
        kafkaCircuitBreaker.onSuccess(0, TimeUnit.MILLISECONDS);
    }

    public void recordKafkaFailure(Throwable throwable) {
        kafkaCircuitBreaker.onError(0, TimeUnit.MILLISECONDS, throwable);
    }

    public void recordRedisSuccess() {
        redisCircuitBreaker.onSuccess(0, TimeUnit.MILLISECONDS);
    }

    public void recordRedisFailure(Throwable throwable) {
        redisCircuitBreaker.onError(0, TimeUnit.MILLISECONDS, throwable);
    }

    public void recordAISuccess() {
        aiCircuitBreaker.onSuccess(0, TimeUnit.MILLISECONDS);
    }

    public void recordAIFailure(Throwable throwable) {
        aiCircuitBreaker.onError(0, TimeUnit.MILLISECONDS, throwable);
    }

    public BackpressureStatus getStatus() {
        return BackpressureStatus.builder()
            .activeRequests(activeRequests.get())
            .maxConcurrentRequests(maxConcurrentRequests)
            .availablePermits(requestSemaphore.availablePermits())
            .rejectedRequests(rejectedRequests.get())
            .timeoutRequests(timeoutRequests.get())
            .kafkaCircuitBreakerState(kafkaCircuitBreaker.getState().toString())
            .redisCircuitBreakerState(redisCircuitBreaker.getState().toString())
            .aiCircuitBreakerState(aiCircuitBreaker.getState().toString())
            .underPressure(activeRequests.get() > maxConcurrentRequests * 0.8)
            .build();
    }

    public void adjustConcurrency(int newMaxConcurrentRequests) {
        if (newMaxConcurrentRequests <= 0 || newMaxConcurrentRequests > 1000) {
            log.warn("Invalid concurrency adjustment: {}", newMaxConcurrentRequests);
            return;
        }

        int delta = newMaxConcurrentRequests - maxConcurrentRequests;
        if (delta > 0) {
            requestSemaphore.release(delta);
        } else if (delta < 0) {
            requestSemaphore.acquireUninterruptibly(-delta);
        }

        maxConcurrentRequests = newMaxConcurrentRequests;
            }

    @lombok.Data
    @lombok.Builder
    public static class BackpressureStatus {
        private int activeRequests;
        private int maxConcurrentRequests;
        private int availablePermits;
        private long rejectedRequests;
        private long timeoutRequests;
        private String kafkaCircuitBreakerState;
        private String redisCircuitBreakerState;
        private String aiCircuitBreakerState;
        private boolean underPressure;
    }
}
