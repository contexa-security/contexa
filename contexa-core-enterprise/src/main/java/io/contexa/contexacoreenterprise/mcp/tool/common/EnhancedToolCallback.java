package io.contexa.contexacoreenterprise.mcp.tool.common;

import io.contexa.contexacoreenterprise.dashboard.metrics.mcp.MCPToolMetrics;
import io.contexa.contexacommon.annotation.SoarTool;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Getter
@Builder
public class EnhancedToolCallback implements ToolCallback {

    public enum ToolType {
        SOAR("SOAR security tool"),
        MCP("MCP external tool"),
        FALLBACK("Fallback tool"),
        NATIVE("Native Spring AI tool");
        
        private final String description;
        
        ToolType(String description) {
            this.description = description;
        }
    }

    private final ToolCallback delegate;
    private final ToolType toolType;

    @Builder.Default
    private final SoarTool.RiskLevel riskLevel = SoarTool.RiskLevel.MEDIUM;
    
    @Builder.Default
    private final Map<String, Object> metadata = new ConcurrentHashMap<>();
    
    @Builder.Default
    private final boolean requiresApproval = false;
    
    @Builder.Default
    private final boolean securityValidation = false;
    
    private final String source;  
    private final String category; 

    private final MCPToolMetrics metricsCollector;

    @Builder.Default
    private final ExecutionStats stats = new ExecutionStats();

    @Override
    public ToolDefinition getToolDefinition() {
        return delegate.getToolDefinition();
    }

    @Override
    public String call(String arguments) {
        long startTime = System.currentTimeMillis();
        String result = null;
        boolean success = false;
        
        try {
            if (securityValidation) {
                validateSecurity(arguments);
            }

            result = delegate.call(arguments);
            success = true;

            return result;

        } catch (Exception e) {
            log.error("Tool execution failed: {} - {}", getToolName(), e.getMessage(), e);
            handleExecutionError(e);
            throw new RuntimeException("Tool execution failed: " + e.getMessage(), e);

        } finally {
            
            long executionTime = System.currentTimeMillis() - startTime;
            stats.record(executionTime, success);

            if (metricsCollector != null) {
                long durationNanos = executionTime * 1_000_000; 
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("tool", getToolName());
                metadata.put("duration", durationNanos);
                metadata.put("success", success);
                metadata.put("toolType", toolType.name());
                metadata.put("source", source);

                String eventType = success ? "execution_success" : "execution_failure";
                metricsCollector.recordEvent(eventType, metadata);
            }

                    }
    }

    public String getToolName() {
        return delegate.getToolDefinition().name();
    }

    public String getDescription() {
        return String.format("%s - %s (risk level: %s)",
            delegate.getToolDefinition().description(),
            toolType.description,
            riskLevel);
    }

    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }

    public Object getMetadata(String key) {
        return metadata.get(key);
    }

    private void validateSecurity(String arguments) {
        
        if (riskLevel == SoarTool.RiskLevel.CRITICAL) {
            log.error("Executing CRITICAL risk tool: {}", getToolName());
        }

        if (arguments != null && (arguments.contains("sudo") ||
            arguments.contains("rm -rf"))) {
            throw new SecurityException("Dangerous command detected: " + arguments);
        }
    }
    
    private void handleExecutionError(Exception e) {
        
        stats.recordError(e.getClass().getSimpleName());

        if (e instanceof java.net.SocketTimeoutException) {
            log.error("Network timeout - retryable: {}", getToolName());
        }
    }

    public static class ExecutionStats {
        private long totalExecutions = 0;
        private long successfulExecutions = 0;
        private long totalExecutionTime = 0;
        private long lastExecutionTime = 0;
        private final Map<String, Integer> errorCounts = new ConcurrentHashMap<>();
        
        public synchronized void record(long executionTime, boolean success) {
            totalExecutions++;
            totalExecutionTime += executionTime;
            lastExecutionTime = System.currentTimeMillis();
            
            if (success) {
                successfulExecutions++;
            }
        }
        
        public synchronized void recordError(String errorType) {
            errorCounts.merge(errorType, 1, Integer::sum);
        }
        
        public double getSuccessRate() {
            return totalExecutions > 0 ? 
                (double) successfulExecutions / totalExecutions : 0.0;
        }
        
        public double getAverageExecutionTime() {
            return totalExecutions > 0 ? 
                (double) totalExecutionTime / totalExecutions : 0.0;
        }
        
        public long getTotalExecutions() { return totalExecutions; }
        public long getSuccessfulExecutions() { return successfulExecutions; }
        public long getLastExecutionTime() { return lastExecutionTime; }
        public Map<String, Integer> getErrorCounts() { return new ConcurrentHashMap<>(errorCounts); }
    }
    
}