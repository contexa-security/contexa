package io.contexa.contexacommon.soar.metrics;


public interface ToolExecutionMetrics {

    
    void recordFiltered(String toolName, String reason);
}
