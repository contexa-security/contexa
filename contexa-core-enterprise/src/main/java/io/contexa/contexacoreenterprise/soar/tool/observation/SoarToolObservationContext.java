package io.contexa.contexacoreenterprise.soar.tool.observation;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.observation.ToolCallingObservationContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * SOAR 도구 실행 관찰 컨텍스트
 * Spring AI 1.0.0의 ToolCallingObservationContext와 함께 활용하여 
 * SOAR 특화 메트릭 수집 및 분석 제공
 */
@Slf4j
@Getter
@Builder
public class SoarToolObservationContext {
    
    // SOAR 특화 메트릭
    private final String incidentId;
    private final String organizationId;
    private final String securityAnalyst;
    private final String riskLevel;
    private final boolean approvalRequired;
    private final String approvalStatus;
    private final Instant executionStartTime;
    private final Instant executionEndTime;
    private final Long executionDurationMs;
    
    public boolean isApprovalRequired() {
        return approvalRequired;
    }
    
    // 실행 통계
    private static final AtomicLong totalExecutions = new AtomicLong(0);
    private static final AtomicLong successfulExecutions = new AtomicLong(0);
    private static final AtomicLong failedExecutions = new AtomicLong(0);
    private static final AtomicLong approvalRequiredExecutions = new AtomicLong(0);
    private static final AtomicLong approvedExecutions = new AtomicLong(0);
    private static final AtomicLong rejectedExecutions = new AtomicLong(0);
    
    // 도구별 실행 통계
    private static final Map<String, ToolExecutionMetrics> toolMetrics = new ConcurrentHashMap<>();
    
    /**
     * SOAR 도구 실행 시작 관찰
     */
    public static SoarToolObservationContext observeExecutionStart(
            String toolName,
            String incidentId,
            String organizationId,
            String securityAnalyst,
            String riskLevel,
            boolean approvalRequired,
            List<ToolCallback> toolCallbacks) {
        
        log.info("SOAR 도구 실행 관찰 시작: {} (위험도: {}, 승인 필요: {})", 
            toolName, riskLevel, approvalRequired);
        
        // Spring AI ToolCallingObservationContext 초기화
        Instant startTime = Instant.now();
        
        // 통계 업데이트
        totalExecutions.incrementAndGet();
        if (approvalRequired) {
            approvalRequiredExecutions.incrementAndGet();
        }
        
        // 도구별 메트릭 업데이트
        toolMetrics.computeIfAbsent(toolName, k -> new ToolExecutionMetrics(toolName))
            .incrementExecution();
        
        return SoarToolObservationContext.builder()
            .incidentId(incidentId)
            .organizationId(organizationId)
            .securityAnalyst(securityAnalyst)
            .riskLevel(riskLevel)
            .approvalRequired(approvalRequired)
            .approvalStatus(approvalRequired ? "PENDING" : "N/A")
            .executionStartTime(startTime)
            .build();
    }
    
    /**
     * SOAR 도구 실행 완료 관찰
     */
    public SoarToolObservationContext observeExecutionEnd(
            boolean success,
            String result,
            Exception error,
            String finalApprovalStatus) {
        
        Instant endTime = Instant.now();
        long durationMs = endTime.toEpochMilli() - executionStartTime.toEpochMilli();
        
        log.info("SOAR 도구 실행 관찰 완료: {} ms (성공: {}, 승인 상태: {})", 
            durationMs, success, finalApprovalStatus);
        
        // 전역 통계 업데이트
        if (success) {
            successfulExecutions.incrementAndGet();
        } else {
            failedExecutions.incrementAndGet();
        }
        
        // 승인 통계 업데이트
        if (approvalRequired) {
            if ("APPROVED".equals(finalApprovalStatus)) {
                approvedExecutions.incrementAndGet();
            } else if ("REJECTED".equals(finalApprovalStatus)) {
                rejectedExecutions.incrementAndGet();
            }
        }
        
        return SoarToolObservationContext.builder()
            .incidentId(this.incidentId)
            .organizationId(this.organizationId)
            .securityAnalyst(this.securityAnalyst)
            .riskLevel(this.riskLevel)
            .approvalRequired(this.approvalRequired)
            .approvalStatus(finalApprovalStatus)
            .executionStartTime(this.executionStartTime)
            .executionEndTime(endTime)
            .executionDurationMs(durationMs)
            .build();
    }
    
    /**
     * SOAR 시스템 전체 실행 통계 조회
     */
    public static Map<String, Object> getGlobalExecutionStatistics() {
        return Map.of(
            "totalExecutions", totalExecutions.get(),
            "successfulExecutions", successfulExecutions.get(),
            "failedExecutions", failedExecutions.get(),
            "successRate", calculateSuccessRate(),
            "approvalRequiredExecutions", approvalRequiredExecutions.get(),
            "approvedExecutions", approvedExecutions.get(),
            "rejectedExecutions", rejectedExecutions.get(),
            "approvalRate", calculateApprovalRate(),
            "averageExecutionTime", calculateAverageExecutionTime(),
            "toolMetrics", getToolMetricsMap()
        );
    }
    
    /**
     * 특정 도구 실행 통계 조회
     */
    public static ToolExecutionMetrics getToolExecutionMetrics(String toolName) {
        return toolMetrics.get(toolName);
    }
    
    /**
     * 성공률 계산
     */
    private static double calculateSuccessRate() {
        long total = totalExecutions.get();
        if (total == 0) return 0.0;
        return (double) successfulExecutions.get() / total * 100.0;
    }
    
    /**
     * 승인률 계산
     */
    private static double calculateApprovalRate() {
        long approvalRequired = approvalRequiredExecutions.get();
        if (approvalRequired == 0) return 0.0;
        return (double) approvedExecutions.get() / approvalRequired * 100.0;
    }
    
    /**
     * 평균 실행 시간 계산 (단순화 버전)
     */
    private static double calculateAverageExecutionTime() {
        // 실제 구현에서는 누적 시간을 추적해야 함
        return toolMetrics.values().stream()
            .mapToLong(ToolExecutionMetrics::getAverageExecutionTimeMs)
            .average()
            .orElse(0.0);
    }
    
    /**
     * 도구별 메트릭 맵 변환
     */
    private static Map<String, Object> getToolMetricsMap() {
        Map<String, Object> metrics = new ConcurrentHashMap<>();
        toolMetrics.forEach((toolName, toolMetric) -> {
            metrics.put(toolName, Map.of(
                "executionCount", toolMetric.getExecutionCount(),
                "averageExecutionTime", toolMetric.getAverageExecutionTimeMs(),
                "lastExecutionTime", toolMetric.getLastExecutionTime()
            ));
        });
        return metrics;
    }
    
    /**
     * 관찰 데이터 JSON 변환
     */
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"incidentId\": \"").append(incidentId).append("\",\n");
        json.append("  \"organizationId\": \"").append(organizationId).append("\",\n");
        json.append("  \"securityAnalyst\": \"").append(securityAnalyst).append("\",\n");
        json.append("  \"riskLevel\": \"").append(riskLevel).append("\",\n");
        json.append("  \"approvalRequired\": ").append(approvalRequired).append(",\n");
        json.append("  \"approvalStatus\": \"").append(approvalStatus).append("\",\n");
        json.append("  \"executionStartTime\": \"").append(executionStartTime).append("\",\n");
        if (executionEndTime != null) {
            json.append("  \"executionEndTime\": \"").append(executionEndTime).append("\",\n");
            json.append("  \"executionDurationMs\": ").append(executionDurationMs).append(",\n");
        }
        json.append("  \"timestamp\": \"").append(Instant.now()).append("\"\n");
        json.append("}");
        return json.toString();
    }
    
    /**
     * 도구별 실행 메트릭
     */
    @Getter
    public static class ToolExecutionMetrics {
        private final String toolName;
        private final AtomicLong executionCount = new AtomicLong(0);
        private final AtomicLong totalExecutionTimeMs = new AtomicLong(0);
        private volatile Instant lastExecutionTime;
        
        public ToolExecutionMetrics(String toolName) {
            this.toolName = toolName;
            this.lastExecutionTime = Instant.now();
        }
        
        public void incrementExecution() {
            executionCount.incrementAndGet();
            lastExecutionTime = Instant.now();
        }
        
        public void addExecutionTime(long durationMs) {
            totalExecutionTimeMs.addAndGet(durationMs);
        }
        
        public long getAverageExecutionTimeMs() {
            long executions = executionCount.get();
            if (executions == 0) return 0;
            return totalExecutionTimeMs.get() / executions;
        }
        
        // 추가 getter 메서드들
        public long getExecutionCount() {
            return executionCount.get();
        }
        
        public Instant getLastExecutionTime() {
            return lastExecutionTime;
        }
    }
}