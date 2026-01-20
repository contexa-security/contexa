package io.contexa.contexamcp.events;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
@Component
@RequiredArgsConstructor
public class SimpleToolEventListener {
    
    private final ConcurrentHashMap<String, AtomicLong> executionCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> successCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> failureCounts = new ConcurrentHashMap<>();
    
    
    @EventListener
    public void onToolExecuted(ToolExecutedEvent event) {
        String toolName = event.getToolName();
        
        
        executionCounts.computeIfAbsent(toolName, k -> new AtomicLong(0)).incrementAndGet();
        
        if (event.isSuccess()) {
            successCounts.computeIfAbsent(toolName, k -> new AtomicLong(0)).incrementAndGet();
            
            log.info("Tool executed successfully - Name: {}, ExecutionId: {}, Time: {}ms, User: {}",
                toolName,
                event.getExecutionId(),
                event.getExecutionTimeMs(),
                event.getUserId());
        } else {
            failureCounts.computeIfAbsent(toolName, k -> new AtomicLong(0)).incrementAndGet();
            
            log.error("Tool execution failed - Name: {}, ExecutionId: {}, Error: {}, User: {}",
                toolName,
                event.getExecutionId(),
                event.getErrorMessage(),
                event.getUserId());
        }
        
        
        if (event.isCritical()) {
            log.warn("CRITICAL: High-risk tool executed - Name: {}, User: {}, Success: {}",
                toolName,
                event.getUserId(),
                event.isSuccess());
        }
    }
    
    
    public ToolStatistics getToolStatistics(String toolName) {
        long executions = executionCounts.getOrDefault(toolName, new AtomicLong(0)).get();
        long successes = successCounts.getOrDefault(toolName, new AtomicLong(0)).get();
        long failures = failureCounts.getOrDefault(toolName, new AtomicLong(0)).get();
        
        double successRate = executions > 0 ? (double) successes / executions * 100 : 0.0;
        
        return ToolStatistics.builder()
            .toolName(toolName)
            .totalExecutions(executions)
            .successCount(successes)
            .failureCount(failures)
            .successRate(successRate)
            .build();
    }
    
    
    @lombok.Data
    @lombok.Builder
    public static class ToolStatistics {
        private String toolName;
        private long totalExecutions;
        private long successCount;
        private long failureCount;
        private double successRate;
    }
}