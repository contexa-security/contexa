package io.contexa.contexacoreenterprise.dashboard.metrics.soar;

import io.contexa.contexacoreenterprise.dashboard.core.AbstractMicrometerMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tool 실행 메트릭
 *
 * SOAR 도구 실행 관련 메트릭을 수집하고 모니터링합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
@Component
public class ToolExecutionMetrics extends AbstractMicrometerMetrics {

    private final Map<String, ToolMetrics> toolMetricsMap = new ConcurrentHashMap<>();
    private final AtomicLong totalExecutions = new AtomicLong(0);
    private final AtomicLong totalApprovals = new AtomicLong(0);
    private final AtomicLong totalRejections = new AtomicLong(0);

    // Micrometer 메트릭
    private Counter executionCounter;
    private Counter approvalCounter;
    private Counter rejectionCounter;
    private Timer executionTimer;

    public ToolExecutionMetrics(MeterRegistry meterRegistry) {
        super(meterRegistry, "soar");
    }

    @Override
    protected void initializeCounters() {
        executionCounter = counterBuilder("tool.executions", "Total tool executions")
                .register(meterRegistry);

        approvalCounter = counterBuilder("tool.approvals", "Total tool approvals")
                .register(meterRegistry);

        rejectionCounter = counterBuilder("tool.rejections", "Total tool rejections")
                .register(meterRegistry);
    }

    @Override
    protected void initializeTimers() {
        executionTimer = timerBuilder("tool.execution.time", "Tool execution time")
                .register(meterRegistry);
    }

    @Override
    protected void initializeGauges() {
        meterRegistry.gauge("soar.tool.approval.rate", this, metrics -> {
            long total = metrics.totalApprovals.get() + metrics.totalRejections.get();
            return total > 0 ? (double) metrics.totalApprovals.get() / total : 0.0;
        });
    }

    // ===== Public API =====

    /**
     * 도구 실행 기록
     */
    public void recordExecution(String toolName, long executionTime, boolean success) {
        totalExecutions.incrementAndGet();

        ToolMetrics metrics = toolMetricsMap.computeIfAbsent(toolName,
                k -> new ToolMetrics(toolName));

        metrics.recordExecution(executionTime, success);

        executionCounter.increment();
        executionTimer.record(Duration.ofMillis(executionTime));

        log.debug("도구 실행 기록: {} - {}ms, 성공={}", toolName, executionTime, success);
    }

    /**
     * 승인 기록
     */
    public void recordApproval(String toolName, boolean approved, long responseTime) {
        if (approved) {
            totalApprovals.incrementAndGet();
            approvalCounter.increment();
        } else {
            totalRejections.incrementAndGet();
            rejectionCounter.increment();
        }

        ToolMetrics metrics = toolMetricsMap.computeIfAbsent(toolName,
                k -> new ToolMetrics(toolName));

        metrics.recordApproval(approved, responseTime);

        log.debug("승인 기록: {} - 승인={}, 응답시간={}ms", toolName, approved, responseTime);
    }

    /**
     * 도구 필터링 기록
     */
    public void recordFiltered(String toolName, String reason) {
        ToolMetrics metrics = toolMetricsMap.computeIfAbsent(toolName,
                k -> new ToolMetrics(toolName));

        metrics.recordFiltered(reason);

        Counter filteredCounter = counterBuilder("tool.filtered", "Filtered tools")
                .tag("reason", reason)
                .register(meterRegistry);
        filteredCounter.increment();

        log.debug("도구 필터링 기록: {} - 이유={}", toolName, reason);
    }

    /**
     * 도구별 메트릭 조회
     */
    public ToolMetrics getToolMetrics(String toolName) {
        return toolMetricsMap.get(toolName);
    }

    /**
     * 전체 메트릭 조회
     */
    public Map<String, Object> getAllMetrics() {
        Map<String, Object> metrics = new ConcurrentHashMap<>();
        metrics.put("totalExecutions", totalExecutions.get());
        metrics.put("totalApprovals", totalApprovals.get());
        metrics.put("totalRejections", totalRejections.get());
        metrics.put("approvalRate", getApprovalRate());
        metrics.put("toolMetrics", toolMetricsMap);
        return metrics;
    }

    public double getApprovalRate() {
        long total = totalApprovals.get() + totalRejections.get();
        return total > 0 ? (double) totalApprovals.get() / total : 0.0;
    }

    @Override
    public double getHealthScore() {
        // 승인율이 50% 이상이면 정상
        double approvalRate = getApprovalRate();
        if (approvalRate < 0.5) {
            return 0.7;
        }
        return 1.0;
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("approvalRate", getApprovalRate());
        metrics.put("totalExecutions", (double) totalExecutions.get());
        metrics.put("totalApprovals", (double) totalApprovals.get());
        metrics.put("totalRejections", (double) totalRejections.get());
        return metrics;
    }

    @Override
    public void reset() {
        super.reset();
        toolMetricsMap.clear();
        totalExecutions.set(0);
        totalApprovals.set(0);
        totalRejections.set(0);
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
