package io.contexa.contexamcp.events;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Simple Tool Event Listener
 * 도구 실행 이벤트를 로깅하고 간단한 메트릭 수집
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SimpleToolEventListener {
    
    private final ConcurrentHashMap<String, AtomicLong> executionCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> successCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> failureCounts = new ConcurrentHashMap<>();
    
    /**
     * 도구 실행 이벤트 처리
     */
    @EventListener
    public void onToolExecuted(ToolExecutedEvent event) {
        String toolName = event.getToolName();
        
        // 실행 카운트 증가
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
        
        // Critical 도구 실행 시 추가 로깅
        if (event.isCritical()) {
            log.warn("CRITICAL: High-risk tool executed - Name: {}, User: {}, Success: {}",
                toolName,
                event.getUserId(),
                event.isSuccess());
        }
    }
    
    /**
     * 도구별 통계 조회 (디버깅용)
     */
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
    
    /**
     * 도구 통계 DTO
     */
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