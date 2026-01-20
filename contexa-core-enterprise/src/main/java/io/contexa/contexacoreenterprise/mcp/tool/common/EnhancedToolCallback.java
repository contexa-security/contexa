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
        SOAR("SOAR 보안 도구"),
        MCP("MCP 외부 도구"),
        FALLBACK("Fallback 도구"),
        NATIVE("Native Spring AI 도구");
        
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
    private final boolean contextAware = false;
    
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
            
            beforeExecution(arguments);
            
            
            if (securityValidation) {
                validateSecurity(arguments);
            }
            
            
            if (contextAware) {
                arguments = enrichWithContext(arguments);
            }
            
            
            result = delegate.call(arguments);
            success = true;

            
            afterExecution(result);

            return result;

        } catch (Exception e) {
            log.error("도구 실행 실패: {} - {}", getToolName(), e.getMessage(), e);
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

            log.trace("도구 실행 완료: {} ({}ms, 성공: {})",
                getToolName(), executionTime, success);
        }
    }
    
    
    public String getToolName() {
        return delegate.getToolDefinition().name();
    }
    
    
    public String getDescription() {
        return String.format("%s - %s (위험도: %s)", 
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
    
    
    
    private void beforeExecution(String arguments) {
        log.trace("도구 실행 시작: {} (타입: {}, 위험도: {})", 
            getToolName(), toolType, riskLevel);
        
        
        if (requiresApproval) {
            log.debug("승인 필요 도구: {}", getToolName());
            
        }
    }
    
    private void afterExecution(String result) {
        log.trace("도구 실행 성공: {}", getToolName());
        
        
        if (metadata.containsKey("cache_results") && 
            Boolean.TRUE.equals(metadata.get("cache_results"))) {
            
        }
    }
    
    private void validateSecurity(String arguments) {
        
        if (riskLevel == SoarTool.RiskLevel.CRITICAL) {
            log.warn("CRITICAL 위험도 도구 실행: {}", getToolName());
        }
        
        
        if (arguments != null && arguments.contains("sudo") || 
            arguments.contains("rm -rf")) {
            throw new SecurityException("위험한 명령어 감지: " + arguments);
        }
    }
    
    private String enrichWithContext(String arguments) {
        
        
        return arguments;
    }
    
    private void handleExecutionError(Exception e) {
        
        stats.recordError(e.getClass().getSimpleName());
        
        
        if (e instanceof java.net.SocketTimeoutException) {
            log.warn("네트워크 타임아웃 - 재시도 가능: {}", getToolName());
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