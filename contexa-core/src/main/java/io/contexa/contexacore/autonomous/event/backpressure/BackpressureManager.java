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

/**
 * Backpressure 관리 시스템
 *
 * 기능:
 * - 시스템 과부하 방지
 * - Circuit Breaker 패턴
 * - 동적 처리량 조절
 * - 리소스 보호
 */
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

    // Semaphore for concurrency control
    private Semaphore requestSemaphore;

    // Circuit Breakers
    private CircuitBreaker kafkaCircuitBreaker;
    private CircuitBreaker redisCircuitBreaker;
    private CircuitBreaker aiCircuitBreaker;

    // Metrics
    private final AtomicInteger activeRequests = new AtomicInteger(0);
    private final AtomicLong rejectedRequests = new AtomicLong(0);
    private final AtomicLong timeoutRequests = new AtomicLong(0);

    public BackpressureManager(MeterRegistry meterRegistry, CircuitBreakerRegistry circuitBreakerRegistry) {
        this.meterRegistry = meterRegistry;
        this.circuitBreakerRegistry = circuitBreakerRegistry;
    }

    @PostConstruct
    public void initialize() {
        // Semaphore 초기화
        requestSemaphore = new Semaphore(maxConcurrentRequests);

        // Circuit Breaker 설정
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

        // Metrics 등록
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

        log.info("BackpressureManager initialized: maxConcurrentRequests={}, timeoutMs={}, failureRate={}%",
            maxConcurrentRequests, timeoutMs, circuitBreakerFailureRate);
    }

    /**
     * 요청 허용 여부 확인 및 획득
     *
     * @return true if permit acquired, false if rejected
     */
    public boolean tryAcquire() {
        try {
            boolean acquired = requestSemaphore.tryAcquire(timeoutMs, TimeUnit.MILLISECONDS);
            if (acquired) {
                activeRequests.incrementAndGet();
                log.debug("Request permit acquired: active={}, available={}",
                    activeRequests.get(), requestSemaphore.availablePermits());
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

    /**
     * 요청 완료 시 permit 반환
     */
    public void release() {
        requestSemaphore.release();
        activeRequests.decrementAndGet();
        log.debug("Request permit released: active={}, available={}",
            activeRequests.get(), requestSemaphore.availablePermits());
    }

    /**
     * Kafka Circuit Breaker 확인
     */
    public boolean isKafkaAvailable() {
        CircuitBreaker.State state = kafkaCircuitBreaker.getState();
        boolean available = state == CircuitBreaker.State.CLOSED || state == CircuitBreaker.State.HALF_OPEN;

        if (!available) {
            log.warn("Kafka circuit breaker is OPEN: state={}", state);
        }

        return available;
    }

    /**
     * Redis Circuit Breaker 확인
     */
    public boolean isRedisAvailable() {
        CircuitBreaker.State state = redisCircuitBreaker.getState();
        boolean available = state == CircuitBreaker.State.CLOSED || state == CircuitBreaker.State.HALF_OPEN;

        if (!available) {
            log.warn("Redis circuit breaker is OPEN: state={}", state);
        }

        return available;
    }

    /**
     * AI Inference Circuit Breaker 확인
     */
    public boolean isAIAvailable() {
        CircuitBreaker.State state = aiCircuitBreaker.getState();
        boolean available = state == CircuitBreaker.State.CLOSED || state == CircuitBreaker.State.HALF_OPEN;

        if (!available) {
            log.warn("AI inference circuit breaker is OPEN: state={}", state);
        }

        return available;
    }

    /**
     * Kafka 작업 성공 기록
     */
    public void recordKafkaSuccess() {
        kafkaCircuitBreaker.onSuccess(0, TimeUnit.MILLISECONDS);
    }

    /**
     * Kafka 작업 실패 기록
     */
    public void recordKafkaFailure(Throwable throwable) {
        kafkaCircuitBreaker.onError(0, TimeUnit.MILLISECONDS, throwable);
    }

    /**
     * Redis 작업 성공 기록
     */
    public void recordRedisSuccess() {
        redisCircuitBreaker.onSuccess(0, TimeUnit.MILLISECONDS);
    }

    /**
     * Redis 작업 실패 기록
     */
    public void recordRedisFailure(Throwable throwable) {
        redisCircuitBreaker.onError(0, TimeUnit.MILLISECONDS, throwable);
    }

    /**
     * AI 작업 성공 기록
     */
    public void recordAISuccess() {
        aiCircuitBreaker.onSuccess(0, TimeUnit.MILLISECONDS);
    }

    /**
     * AI 작업 실패 기록
     */
    public void recordAIFailure(Throwable throwable) {
        aiCircuitBreaker.onError(0, TimeUnit.MILLISECONDS, throwable);
    }

    /**
     * Backpressure 상태 확인
     */
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

    /**
     * 동적 Concurrency 조정 (선택적)
     */
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
        log.info("Concurrency adjusted: newMax={}, active={}",
            maxConcurrentRequests, activeRequests.get());
    }

    /**
     * Backpressure 상태 모델
     */
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
