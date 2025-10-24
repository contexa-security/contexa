package io.contexa.contexacore.mcp.tool.observation;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * MetricsCollector
 * 
 * 도구 실행 및 해결 메트릭을 수집합니다.
 * Micrometer를 사용하여 메트릭을 외부 모니터링 시스템으로 전송합니다.
 */
@Component
@Slf4j
public class MetricsCollector {
    
    private final MeterRegistry meterRegistry;
    private final Map<String, AtomicLong> resolverMetrics = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> executionMetrics = new ConcurrentHashMap<>();
    
    // 카운터
    private final Counter totalResolutions;
    private final Counter successfulResolutions;
    private final Counter failedResolutions;
    private final Counter totalExecutions;
    private final Counter successfulExecutions;
    private final Counter failedExecutions;
    
    // 타이머
    private final Timer resolutionTimer;
    private final Timer executionTimer;
    
    public MetricsCollector(@Autowired(required = false) MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        
        if (meterRegistry != null) {
            // 카운터 초기화
            this.totalResolutions = Counter.builder("tool.resolution.total")
                .description("Total tool resolutions")
                .register(meterRegistry);
                
            this.successfulResolutions = Counter.builder("tool.resolution.success")
                .description("Successful tool resolutions")
                .register(meterRegistry);
                
            this.failedResolutions = Counter.builder("tool.resolution.failed")
                .description("Failed tool resolutions")
                .register(meterRegistry);
                
            this.totalExecutions = Counter.builder("tool.execution.total")
                .description("Total tool executions")
                .register(meterRegistry);
                
            this.successfulExecutions = Counter.builder("tool.execution.success")
                .description("Successful tool executions")
                .register(meterRegistry);
                
            this.failedExecutions = Counter.builder("tool.execution.failed")
                .description("Failed tool executions")
                .register(meterRegistry);
                
            // 타이머 초기화
            this.resolutionTimer = Timer.builder("tool.resolution.time")
                .description("Tool resolution time")
                .register(meterRegistry);
                
            this.executionTimer = Timer.builder("tool.execution.time")
                .description("Tool execution time")
                .register(meterRegistry);
                
            log.info("MetricsCollector 초기화 완료 (Micrometer 활성화)");
        } else {
            // Micrometer가 없는 경우 null 객체 패턴 사용
            this.totalResolutions = null;
            this.successfulResolutions = null;
            this.failedResolutions = null;
            this.totalExecutions = null;
            this.successfulExecutions = null;
            this.failedExecutions = null;
            this.resolutionTimer = null;
            this.executionTimer = null;
            
            log.info("MetricsCollector 초기화 완료 (Micrometer 비활성화)");
        }
    }
    
    /**
     * 도구 해결 메트릭 기록
     */
    public void recordResolution(String resolverName, long elapsedTimeNanos) {
        if (meterRegistry != null) {
            totalResolutions.increment();
            successfulResolutions.increment();
            resolutionTimer.record(elapsedTimeNanos, TimeUnit.NANOSECONDS);
        }
        
        // 내부 메트릭 업데이트
        String key = "resolver." + resolverName;
        resolverMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
        
        log.trace("도구 해결 메트릭 기록: {} - {}ns", resolverName, elapsedTimeNanos);
    }
    
    /**
     * 도구 해결 실패 기록
     */
    public void recordResolutionFailure(String resolverName, Exception error) {
        if (meterRegistry != null) {
            totalResolutions.increment();
            failedResolutions.increment();
        }
        
        String key = "resolver." + resolverName + ".failures";
        resolverMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
        
        log.debug("도구 해결 실패 기록: {} - {}", resolverName, error.getMessage());
    }
    
    /**
     * 전체 해결 시간 기록
     */
    public void recordTotalResolutionTime(long elapsedTimeNanos) {
        if (resolutionTimer != null) {
            resolutionTimer.record(elapsedTimeNanos, TimeUnit.NANOSECONDS);
        }
        
        resolverMetrics.computeIfAbsent("total.resolution.time", k -> new AtomicLong(0))
            .addAndGet(elapsedTimeNanos);
    }
    
    /**
     * 도구 실행 메트릭 기록
     */
    public void recordExecution(String toolName, long elapsedTimeMillis, boolean success) {
        if (meterRegistry != null) {
            totalExecutions.increment();
            if (success) {
                successfulExecutions.increment();
            } else {
                failedExecutions.increment();
            }
            executionTimer.record(Duration.ofMillis(elapsedTimeMillis));
        }
        
        // 내부 메트릭 업데이트
        String key = "execution." + toolName + (success ? ".success" : ".failure");
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
        
        log.trace("도구 실행 메트릭 기록: {} - {}ms (success: {})", 
            toolName, elapsedTimeMillis, success);
    }
    
    /**
     * 도구별 실행 시간 기록
     */
    public void recordToolExecutionTime(String toolName, long elapsedTimeMillis) {
        if (meterRegistry != null) {
            Timer.builder("tool.execution.time.by.name")
                .tag("tool", toolName)
                .register(meterRegistry)
                .record(Duration.ofMillis(elapsedTimeMillis));
        }
        
        String key = "execution." + toolName + ".time";
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0))
            .addAndGet(elapsedTimeMillis);
    }
    
    /**
     * 캐시 히트 기록
     */
    public void recordCacheHit(String toolName) {
        if (meterRegistry != null) {
            Counter.builder("tool.cache.hit")
                .tag("tool", toolName)
                .register(meterRegistry)
                .increment();
        }
        
        String key = "cache." + toolName + ".hits";
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
    }
    
    /**
     * 캐시 미스 기록
     */
    public void recordCacheMiss(String toolName) {
        if (meterRegistry != null) {
            Counter.builder("tool.cache.miss")
                .tag("tool", toolName)
                .register(meterRegistry)
                .increment();
        }
        
        String key = "cache." + toolName + ".misses";
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
    }
    
    /**
     * 승인 요청 기록
     */
    public void recordApprovalRequest(String toolName, boolean approved) {
        if (meterRegistry != null) {
            Counter.builder("tool.approval")
                .tag("tool", toolName)
                .tag("result", approved ? "approved" : "rejected")
                .register(meterRegistry)
                .increment();
        }
        
        String key = "approval." + toolName + (approved ? ".approved" : ".rejected");
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
    }
    
    /**
     * 통계 정보 반환
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new ConcurrentHashMap<>();
        
        // Resolver 메트릭
        stats.put("resolverMetrics", new ConcurrentHashMap<>(resolverMetrics));
        
        // Execution 메트릭
        stats.put("executionMetrics", new ConcurrentHashMap<>(executionMetrics));
        
        // 요약 정보
        long totalResolutionCount = resolverMetrics.entrySet().stream()
            .filter(e -> e.getKey().startsWith("resolver.") && !e.getKey().contains("failures"))
            .mapToLong(e -> e.getValue().get())
            .sum();
            
        long totalExecutionCount = executionMetrics.entrySet().stream()
            .filter(e -> e.getKey().contains(".success"))
            .mapToLong(e -> e.getValue().get())
            .sum();
            
        stats.put("summary", Map.of(
            "totalResolutions", totalResolutionCount,
            "totalExecutions", totalExecutionCount,
            "hasMicrometer", meterRegistry != null
        ));
        
        return stats;
    }
    
    /**
     * 메트릭 리셋
     */
    public void reset() {
        resolverMetrics.clear();
        executionMetrics.clear();
        log.info("메트릭 리셋 완료");
    }
}