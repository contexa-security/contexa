package io.contexa.contexacore.std.llm.metrics;

import lombok.Getter;

@Getter
public class ModelPerformanceMetric {

    private long totalResponseTime = 0;
    private int totalExecutions = 0;
    private int successfulExecutions = 0;

    public synchronized void recordExecution(long responseTime, boolean success) {
        totalResponseTime += responseTime;
        totalExecutions++;
        if (success) {
            successfulExecutions++;
        }
    }

    public synchronized double getAverageResponseTime() {
        return totalExecutions > 0 ? (double) totalResponseTime / totalExecutions : 0;
    }

    public synchronized double getSuccessRate() {
        return totalExecutions > 0 ? (double) successfulExecutions / totalExecutions : 0;
    }

    public synchronized void reset() {
        totalResponseTime = 0;
        totalExecutions = 0;
        successfulExecutions = 0;
    }
}