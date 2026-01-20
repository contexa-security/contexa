package io.contexa.contexacoreenterprise.dashboard.metrics.mcp;

import io.contexa.contexacoreenterprise.dashboard.api.DomainMetrics;
import io.contexa.contexacoreenterprise.dashboard.api.EventRecorder;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
public class MCPToolMetrics implements DomainMetrics, EventRecorder {
    
    private final MeterRegistry meterRegistry;
    private final Map<String, AtomicLong> resolverMetrics = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> executionMetrics = new ConcurrentHashMap<>();
    
    
    private final Counter totalResolutions;
    private final Counter successfulResolutions;
    private final Counter failedResolutions;
    private final Counter totalExecutions;
    private final Counter successfulExecutions;
    private final Counter failedExecutions;
    
    
    private final Timer resolutionTimer;
    private final Timer executionTimer;
    
    public MCPToolMetrics(@Autowired(required = false) MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        
        if (meterRegistry != null) {
            
            this.totalResolutions = Counter.builder("mcp.tool.resolution.total")
                .description("Total tool resolutions")
                .register(meterRegistry);

            this.successfulResolutions = Counter.builder("mcp.tool.resolution.success")
                .description("Successful tool resolutions")
                .register(meterRegistry);

            this.failedResolutions = Counter.builder("mcp.tool.resolution.failed")
                .description("Failed tool resolutions")
                .register(meterRegistry);

            this.totalExecutions = Counter.builder("mcp.tool.execution.total")
                .description("Total tool executions")
                .register(meterRegistry);

            this.successfulExecutions = Counter.builder("mcp.tool.execution.success")
                .description("Successful tool executions")
                .register(meterRegistry);

            this.failedExecutions = Counter.builder("mcp.tool.execution.failed")
                .description("Failed tool executions")
                .register(meterRegistry);

            
            this.resolutionTimer = Timer.builder("mcp.tool.resolution.time")
                .description("Tool resolution time")
                .register(meterRegistry);

            this.executionTimer = Timer.builder("mcp.tool.execution.time")
                .description("Tool execution time")
                .register(meterRegistry);
                
            log.info("MCPToolMetrics 초기화 완료 (Micrometer 활성화)");
        } else {
            
            this.totalResolutions = null;
            this.successfulResolutions = null;
            this.failedResolutions = null;
            this.totalExecutions = null;
            this.successfulExecutions = null;
            this.failedExecutions = null;
            this.resolutionTimer = null;
            this.executionTimer = null;
            
            log.info("MCPToolMetrics 초기화 완료 (Micrometer 비활성화)");
        }
    }
    
    
    public void recordResolution(String resolverName, long elapsedTimeNanos) {
        if (meterRegistry != null) {
            totalResolutions.increment();
            successfulResolutions.increment();
            resolutionTimer.record(elapsedTimeNanos, TimeUnit.NANOSECONDS);
        }
        
        
        String key = "resolver." + resolverName;
        resolverMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
        
        log.trace("도구 해결 메트릭 기록: {} - {}ns", resolverName, elapsedTimeNanos);
    }
    
    
    public void recordResolutionFailure(String resolverName, Exception error) {
        if (meterRegistry != null) {
            totalResolutions.increment();
            failedResolutions.increment();
        }
        
        String key = "resolver." + resolverName + ".failures";
        resolverMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
        
        log.debug("도구 해결 실패 기록: {} - {}", resolverName, error.getMessage());
    }
    
    
    public void recordTotalResolutionTime(long elapsedTimeNanos) {
        if (resolutionTimer != null) {
            resolutionTimer.record(elapsedTimeNanos, TimeUnit.NANOSECONDS);
        }
        
        resolverMetrics.computeIfAbsent("total.resolution.time", k -> new AtomicLong(0))
            .addAndGet(elapsedTimeNanos);
    }
    
    
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
        
        
        String key = "execution." + toolName + (success ? ".success" : ".failure");
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
        
        log.trace("도구 실행 메트릭 기록: {} - {}ms (success: {})", 
            toolName, elapsedTimeMillis, success);
    }
    
    
    public void recordToolExecutionTime(String toolName, long elapsedTimeMillis) {
        if (meterRegistry != null) {
            Timer.builder("mcp.tool.execution.time.by.name")
                .tag("tool", toolName)
                .register(meterRegistry)
                .record(Duration.ofMillis(elapsedTimeMillis));
        }

        String key = "execution." + toolName + ".time";
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0))
            .addAndGet(elapsedTimeMillis);
    }

    
    public void recordCacheHit(String toolName) {
        if (meterRegistry != null) {
            Counter.builder("mcp.tool.cache.hit")
                .tag("tool", toolName)
                .register(meterRegistry)
                .increment();
        }

        String key = "cache." + toolName + ".hits";
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
    }

    
    public void recordCacheMiss(String toolName) {
        if (meterRegistry != null) {
            Counter.builder("mcp.tool.cache.miss")
                .tag("tool", toolName)
                .register(meterRegistry)
                .increment();
        }

        String key = "cache." + toolName + ".misses";
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
    }

    
    public void recordApprovalRequest(String toolName, boolean approved) {
        if (meterRegistry != null) {
            Counter.builder("mcp.tool.approval")
                .tag("tool", toolName)
                .tag("result", approved ? "approved" : "rejected")
                .register(meterRegistry)
                .increment();
        }

        String key = "approval." + toolName + (approved ? ".approved" : ".rejected");
        executionMetrics.computeIfAbsent(key, k -> new AtomicLong(0)).incrementAndGet();
    }
    
    
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new ConcurrentHashMap<>();
        
        
        stats.put("resolverMetrics", new ConcurrentHashMap<>(resolverMetrics));
        
        
        stats.put("executionMetrics", new ConcurrentHashMap<>(executionMetrics));
        
        
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
    
    
    public void reset() {
        resolverMetrics.clear();
        executionMetrics.clear();
        log.info("메트릭 리셋 완료");
    }

    

    @Override
    public String getDomain() {
        return "mcp";
    }

    @Override
    public void initialize() {
        
        log.info("MCPToolMetrics 초기화 완료");
    }

    
    

    

    @Override
    public double getHealthScore() {
        if (meterRegistry == null) return 1.0;

        double totalRes = totalResolutions != null ? totalResolutions.count() : 0;
        double successRes = successfulResolutions != null ? successfulResolutions.count() : 0;
        double totalExec = totalExecutions != null ? totalExecutions.count() : 0;
        double successExec = successfulExecutions != null ? successfulExecutions.count() : 0;

        double resolutionRate = totalRes > 0 ? successRes / totalRes : 1.0;
        double executionRate = totalExec > 0 ? successExec / totalExec : 1.0;

        return (resolutionRate + executionRate) / 2.0;
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        if (meterRegistry != null) {
            metrics.put("resolution_count", totalResolutions != null ? totalResolutions.count() : 0.0);
            metrics.put("execution_count", totalExecutions != null ? totalExecutions.count() : 0.0);
            metrics.put("success_rate", getHealthScore());
        }
        return metrics;
    }

    

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        switch (eventType) {
            case "resolution_success":
                String resolver = metadata.containsKey("resolver") ?
                    (String) metadata.get("resolver") : "unknown";
                long resDuration = metadata.containsKey("duration") ?
                    ((Number) metadata.get("duration")).longValue() : 0L;
                recordResolution(resolver, resDuration);
                break;
            case "resolution_failure":
                String failedResolver = metadata.containsKey("resolver") ?
                    (String) metadata.get("resolver") : "unknown";
                Exception error = metadata.containsKey("error") ?
                    (Exception) metadata.get("error") : new RuntimeException("Unknown error");
                recordResolutionFailure(failedResolver, error);
                break;
            case "execution_success":
                String tool = metadata.containsKey("tool") ?
                    (String) metadata.get("tool") : "unknown";
                long execDuration = metadata.containsKey("duration") ?
                    ((Number) metadata.get("duration")).longValue() : 0L;
                recordExecution(tool, execDuration, true);
                break;
            case "execution_failure":
                String failedTool = metadata.containsKey("tool") ?
                    (String) metadata.get("tool") : "unknown";
                long failedDuration = metadata.containsKey("duration") ?
                    ((Number) metadata.get("duration")).longValue() : 0L;
                recordExecution(failedTool, failedDuration, false);
                break;
            default:
                log.warn("Unknown event type: {}", eventType);
        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        if (meterRegistry == null) return;

        if ("resolution".equals(operationName) && resolutionTimer != null) {
            resolutionTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        } else if ("execution".equals(operationName) && executionTimer != null) {
            executionTimer.record(durationNanos, TimeUnit.NANOSECONDS);
        }
    }
}