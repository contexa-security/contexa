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

@Slf4j
@Getter
@Builder
public class SoarToolObservationContext {

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

    private static final AtomicLong totalExecutions = new AtomicLong(0);
    private static final AtomicLong successfulExecutions = new AtomicLong(0);
    private static final AtomicLong failedExecutions = new AtomicLong(0);
    private static final AtomicLong approvalRequiredExecutions = new AtomicLong(0);
    private static final AtomicLong approvedExecutions = new AtomicLong(0);
    private static final AtomicLong rejectedExecutions = new AtomicLong(0);

    private static final Map<String, ToolExecutionMetrics> toolMetrics = new ConcurrentHashMap<>();

    public static SoarToolObservationContext observeExecutionStart(
            String toolName,
            String incidentId,
            String organizationId,
            String securityAnalyst,
            String riskLevel,
            boolean approvalRequired,
            List<ToolCallback> toolCallbacks) {

        Instant startTime = Instant.now();

        totalExecutions.incrementAndGet();
        if (approvalRequired) {
            approvalRequiredExecutions.incrementAndGet();
        }

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

    public SoarToolObservationContext observeExecutionEnd(
            boolean success,
            String result,
            Exception error,
            String finalApprovalStatus) {
        
        Instant endTime = Instant.now();
        long durationMs = endTime.toEpochMilli() - executionStartTime.toEpochMilli();

        if (success) {
            successfulExecutions.incrementAndGet();
        } else {
            failedExecutions.incrementAndGet();
        }

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

    public static ToolExecutionMetrics getToolExecutionMetrics(String toolName) {
        return toolMetrics.get(toolName);
    }

    private static double calculateSuccessRate() {
        long total = totalExecutions.get();
        if (total == 0) return 0.0;
        return (double) successfulExecutions.get() / total * 100.0;
    }

    private static double calculateApprovalRate() {
        long approvalRequired = approvalRequiredExecutions.get();
        if (approvalRequired == 0) return 0.0;
        return (double) approvedExecutions.get() / approvalRequired * 100.0;
    }

    private static double calculateAverageExecutionTime() {
        
        return toolMetrics.values().stream()
            .mapToLong(ToolExecutionMetrics::getAverageExecutionTimeMs)
            .average()
            .orElse(0.0);
    }

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

        public long getExecutionCount() {
            return executionCount.get();
        }
        
        public Instant getLastExecutionTime() {
            return lastExecutionTime;
        }
    }
}