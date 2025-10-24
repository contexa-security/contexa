package io.contexa.contexacore.soar.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tool 실행 메트릭 수집기
 * 
 * 도구 실행 관련 메트릭을 수집하고 모니터링합니다.
 * Micrometer를 사용하여 표준 메트릭을 제공합니다.
 */
@Slf4j
public class ToolExecutionMetrics {
    
    private final Map<String, ToolMetrics> toolMetricsMap = new ConcurrentHashMap<>();
    private final AtomicLong totalExecutions = new AtomicLong(0);
    private final AtomicLong totalApprovals = new AtomicLong(0);
    private final AtomicLong totalRejections = new AtomicLong(0);
    
    @Autowired(required = false)
    private MeterRegistry meterRegistry;
    
    // Micrometer 메트릭
    private Counter executionCounter;
    private Counter approvalCounter;
    private Counter rejectionCounter;
    private Timer executionTimer;
    
    /**
     * 메트릭 초기화
     */
    public void initialize() {
        if (meterRegistry != null) {
            executionCounter = Counter.builder("soar.tool.executions")
                .description("Total number of tool executions")
                .register(meterRegistry);
            
            approvalCounter = Counter.builder("soar.tool.approvals")
                .description("Total number of tool approvals")
                .register(meterRegistry);
            
            rejectionCounter = Counter.builder("soar.tool.rejections")
                .description("Total number of tool rejections")
                .register(meterRegistry);
            
            executionTimer = Timer.builder("soar.tool.execution.time")
                .description("Tool execution time")
                .register(meterRegistry);
            
            log.info("Micrometer 메트릭 초기화 완료");
        }
    }
    
    /**
     * 도구 실행 기록
     * 
     * @param toolName 도구 이름
     * @param executionTime 실행 시간 (밀리초)
     * @param success 성공 여부
     */
    public void recordExecution(String toolName, long executionTime, boolean success) {
        totalExecutions.incrementAndGet();
        
        ToolMetrics metrics = toolMetricsMap.computeIfAbsent(toolName, 
            k -> new ToolMetrics(toolName));
        
        metrics.recordExecution(executionTime, success);
        
        // Micrometer 메트릭 업데이트
        if (meterRegistry != null && executionCounter != null) {
            executionCounter.increment();
            if (executionTimer != null) {
                executionTimer.record(Duration.ofMillis(executionTime));
            }
        }
        
        log.debug("도구 실행 기록: {} - {}ms, 성공={}", toolName, executionTime, success);
    }
    
    /**
     * 승인 기록
     * 
     * @param toolName 도구 이름
     * @param approved 승인 여부
     * @param responseTime 응답 시간 (밀리초)
     */
    public void recordApproval(String toolName, boolean approved, long responseTime) {
        if (approved) {
            totalApprovals.incrementAndGet();
            if (approvalCounter != null) {
                approvalCounter.increment();
            }
        } else {
            totalRejections.incrementAndGet();
            if (rejectionCounter != null) {
                rejectionCounter.increment();
            }
        }
        
        ToolMetrics metrics = toolMetricsMap.computeIfAbsent(toolName, 
            k -> new ToolMetrics(toolName));
        
        metrics.recordApproval(approved, responseTime);
        
        log.debug("승인 기록: {} - 승인={}, 응답시간={}ms", toolName, approved, responseTime);
    }
    
    /**
     * 도구 필터링 기록
     * 
     * @param toolName 도구 이름
     * @param reason 필터링 이유
     */
    public void recordFiltered(String toolName, String reason) {
        ToolMetrics metrics = toolMetricsMap.computeIfAbsent(toolName, 
            k -> new ToolMetrics(toolName));
        
        metrics.recordFiltered(reason);
        
        // Micrometer 메트릭 업데이트 (필터링 카운터)
        if (meterRegistry != null) {
            Counter filteredCounter = Counter.builder("soar.tool.filtered")
                .description("Total number of filtered tools")
                .tag("reason", reason)
                .register(meterRegistry);
            filteredCounter.increment();
        }
        
        log.debug("도구 필터링 기록: {} - 이유={}", toolName, reason);
    }
    
    /**
     * 도구별 메트릭 조회
     * 
     * @param toolName 도구 이름
     * @return 도구 메트릭
     */
    public ToolMetrics getToolMetrics(String toolName) {
        return toolMetricsMap.get(toolName);
    }
    
    /**
     * 전체 메트릭 조회
     * 
     * @return 전체 메트릭 맵
     */
    public Map<String, Object> getAllMetrics() {
        Map<String, Object> metrics = new ConcurrentHashMap<>();
        metrics.put("totalExecutions", totalExecutions.get());
        metrics.put("totalApprovals", totalApprovals.get());
        metrics.put("totalRejections", totalRejections.get());
        metrics.put("approvalRate", calculateApprovalRate());
        metrics.put("toolMetrics", toolMetricsMap);
        return metrics;
    }
    
    /**
     * 승인율 계산
     * 
     * @return 승인율 (0.0 ~ 1.0)
     */
    private double calculateApprovalRate() {
        long total = totalApprovals.get() + totalRejections.get();
        if (total == 0) {
            return 0.0;
        }
        return (double) totalApprovals.get() / total;
    }
    
    /**
     * 메트릭 리셋
     */
    public void reset() {
        toolMetricsMap.clear();
        totalExecutions.set(0);
        totalApprovals.set(0);
        totalRejections.set(0);
        log.info("메트릭 리셋 완료");
    }
    
    /**
     * 도구별 메트릭 클래스
     */
    @Data
    public static class ToolMetrics {
        private final String toolName;
        private long totalExecutions = 0;
        private long successfulExecutions = 0;
        private long failedExecutions = 0;
        private long totalExecutionTime = 0;
        private long minExecutionTime = Long.MAX_VALUE;
        private long maxExecutionTime = 0;
        private long totalApprovals = 0;
        private long totalRejections = 0;
        private long totalApprovalTime = 0;
        private long totalFiltered = 0;
        private final Map<String, Long> filteredReasons = new ConcurrentHashMap<>();
        private LocalDateTime lastExecutionTime;
        
        public ToolMetrics(String toolName) {
            this.toolName = toolName;
        }
        
        public synchronized void recordExecution(long executionTime, boolean success) {
            totalExecutions++;
            totalExecutionTime += executionTime;
            
            if (success) {
                successfulExecutions++;
            } else {
                failedExecutions++;
            }
            
            if (executionTime < minExecutionTime) {
                minExecutionTime = executionTime;
            }
            if (executionTime > maxExecutionTime) {
                maxExecutionTime = executionTime;
            }
            
            lastExecutionTime = LocalDateTime.now();
        }
        
        public synchronized void recordApproval(boolean approved, long responseTime) {
            if (approved) {
                totalApprovals++;
            } else {
                totalRejections++;
            }
            totalApprovalTime += responseTime;
        }
        
        public synchronized void recordFiltered(String reason) {
            totalFiltered++;
            filteredReasons.merge(reason, 1L, Long::sum);
        }
        
        public double getSuccessRate() {
            if (totalExecutions == 0) {
                return 0.0;
            }
            return (double) successfulExecutions / totalExecutions;
        }
        
        public double getAverageExecutionTime() {
            if (totalExecutions == 0) {
                return 0.0;
            }
            return (double) totalExecutionTime / totalExecutions;
        }
        
        public double getApprovalRate() {
            long total = totalApprovals + totalRejections;
            if (total == 0) {
                return 0.0;
            }
            return (double) totalApprovals / total;
        }
        
        public double getAverageApprovalTime() {
            long total = totalApprovals + totalRejections;
            if (total == 0) {
                return 0.0;
            }
            return (double) totalApprovalTime / total;
        }
    }
}