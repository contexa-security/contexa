package io.contexa.contexacoreenterprise.mcp.integration;

import io.contexa.contexacoreenterprise.mcp.tool.common.EnhancedToolCallback;
import io.contexa.contexacommon.annotation.SoarTool;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class UnifiedToolCallbackProvider implements ToolCallbackProvider {
    
    @Autowired(required = false)
    @Qualifier("soarToolIntegrationProvider")
    private ToolIntegrationProvider soarProvider;
    
    @Autowired(required = false)
    @Qualifier("mcpToolIntegrationAdapter")
    private ToolIntegrationProvider mcpProvider;

    private final Map<String, EnhancedToolCallback> unifiedTools = new ConcurrentHashMap<>();

    private final Map<String, ToolExecutionStats> executionStats = new ConcurrentHashMap<>();
    private final AtomicLong totalExecutions = new AtomicLong(0);

    private final Map<String, Object> sharedContext = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initializeUnifiedProvider() {

        registerSoarTools();

        registerMcpTools();

        logIntegrationStatus();
    }

    @Override
    public ToolCallback[] getToolCallbacks() {
        return unifiedTools.values().toArray(new ToolCallback[0]);
    }

    public Optional<EnhancedToolCallback> getUnifiedToolCallback(String name) {
        return Optional.ofNullable(unifiedTools.get(name));
    }

    public ToolCallback[] getToolCallbacksByType(EnhancedToolCallback.ToolType type) {
        return unifiedTools.values().stream()
            .filter(tool -> tool.getToolType() == type)
            .toArray(ToolCallback[]::new);
    }

    public ToolCallback[] getToolCallbacksByRiskLevel(SoarTool.RiskLevel... levels) {
        Set<SoarTool.RiskLevel> levelSet = new HashSet<>(Arrays.asList(levels));
        
        return unifiedTools.values().stream()
            .filter(tool -> levelSet.contains(tool.getRiskLevel()))
            .toArray(ToolCallback[]::new);
    }

    public boolean requiresApproval(String toolName) {
        EnhancedToolCallback tool = unifiedTools.get(toolName);
        if (tool == null) return false;

        if (tool.isRequiresApproval()) {
            return true;
        }

        if (tool.getToolType() == EnhancedToolCallback.ToolType.SOAR && soarProvider != null) {
            return soarProvider.requiresApproval(toolName);
        }
        
        if (tool.getToolType() == EnhancedToolCallback.ToolType.MCP && mcpProvider != null) {
            return mcpProvider.requiresApproval(toolName);
        }
        
        return false;
    }

    public CompletableFuture<String> executeToolWithContext(String toolName, String arguments, 
                                                           Map<String, Object> executionContext) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                EnhancedToolCallback tool = unifiedTools.get(toolName);
                if (tool == null) {
                    throw new IllegalArgumentException("도구를 찾을 수 없음: " + toolName);
                }

                prepareExecutionContext(toolName, executionContext);

                long startTime = System.currentTimeMillis();
                ToolExecutionStats stats = executionStats.computeIfAbsent(toolName, 
                    k -> new ToolExecutionStats(toolName));

                String result = tool.call(arguments);

                long executionTime = System.currentTimeMillis() - startTime;
                stats.recordExecution(executionTime, true);
                totalExecutions.incrementAndGet();

                updateSharedContext(toolName, result, executionContext);
                
                                return result;
                
            } catch (Exception e) {
                
                ToolExecutionStats stats = executionStats.get(toolName);
                if (stats != null) {
                    stats.recordExecution(0, false);
                }
                
                log.error("도구 실행 실패: {} - {}", toolName, e.getMessage(), e);

                return handleToolExecutionFailure(toolName, arguments, e);
            }
        });
    }

    public UnifiedIntegrationStats getUnifiedIntegrationStats() {
        int soarToolCount = (int) unifiedTools.values().stream()
            .filter(tool -> tool.getToolType() == EnhancedToolCallback.ToolType.SOAR).count();
        
        int mcpToolCount = (int) unifiedTools.values().stream()
            .filter(tool -> tool.getToolType() == EnhancedToolCallback.ToolType.MCP).count();
        
        return new UnifiedIntegrationStats(
            soarToolCount,
            mcpToolCount,
            unifiedTools.size(),
            totalExecutions.get(),
            mcpProvider != null,
            System.currentTimeMillis()
        );
    }

    private void registerSoarTools() {
        if (soarProvider == null) {
                        return;
        }
        
        try {
            ToolCallback[] soarTools = soarProvider.getToolCallbacks();
            
            for (ToolCallback soarTool : soarTools) {
                String toolName = soarTool.getToolDefinition().name();
                SoarTool.RiskLevel riskLevel = soarProvider.getToolRiskLevel(toolName);
                
                EnhancedToolCallback unifiedTool = EnhancedToolCallback.builder()
                    .delegate(soarTool)
                    .toolType(EnhancedToolCallback.ToolType.SOAR)
                    .riskLevel(riskLevel)
                    .securityValidation(true)
                    .requiresApproval(riskLevel == SoarTool.RiskLevel.HIGH || 
                                     riskLevel == SoarTool.RiskLevel.CRITICAL)
                    .source("SoarProvider")
                    .category("SOAR")
                    .build();
                
                unifiedTools.put(toolName, unifiedTool);
                            }

        } catch (Exception e) {
            log.warn("SOAR 도구 등록 실패: {}", e.getMessage());
        }
    }

    private void registerMcpTools() {
        if (mcpProvider == null) {
                        return;
        }
        
        try {
            ToolCallback[] mcpTools = mcpProvider.getToolCallbacks();
            
            for (ToolCallback mcpTool : mcpTools) {
                String toolName = mcpTool.getToolDefinition().name();

                EnhancedToolCallback unifiedTool = EnhancedToolCallback.builder()
                    .delegate(mcpTool)
                    .toolType(EnhancedToolCallback.ToolType.MCP)
                    .riskLevel(SoarTool.RiskLevel.LOW)
                    .contextAware(true)
                    .source("McpProvider")
                    .category("MCP")
                    .build();
                
                unifiedTools.put(toolName, unifiedTool);
                            }

        } catch (Exception e) {
            log.warn("MCP 도구 등록 실패: {}", e.getMessage());
        }
    }

    private boolean assessMcpToolRisk(String toolName) {
        
        return false;
    }

    private void prepareExecutionContext(String toolName, Map<String, Object> context) {
        
        context.putAll(sharedContext);
        context.put("executionId", UUID.randomUUID().toString());
        context.put("timestamp", System.currentTimeMillis());
        context.put("toolName", toolName);
    }

    private void updateSharedContext(String toolName, String result, Map<String, Object> context) {
        sharedContext.put("lastExecutedTool", toolName);
        sharedContext.put("lastExecutionResult", result);
        sharedContext.put("lastExecutionTime", System.currentTimeMillis());

        String historyKey = "history_" + toolName;
        @SuppressWarnings("unchecked")
        List<String> history = (List<String>) sharedContext.computeIfAbsent(historyKey, 
            k -> new ArrayList<String>());
        
        history.add(result);
        if (history.size() > 5) {
            history.remove(0);
        }
    }

    private String handleToolExecutionFailure(String toolName, String arguments, Exception error) {
        
        log.error("도구 실행 실패 - 도구: {}, 인수: {}, 오류: {}", toolName, arguments, error.getMessage());

        if (toolName.contains("search")) {
            return "검색 서비스 일시 불가, 나중에 다시 시도해주세요: " + error.getMessage();
        }
        
        if (toolName.contains("security") || toolName.contains("scan")) {
            return "보안 도구 일시 불가, 시스템 관리자에게 문의하세요: " + error.getMessage();
        }

        if (unifiedTools.containsKey(toolName) && 
            unifiedTools.get(toolName).getToolType() == EnhancedToolCallback.ToolType.SOAR) {
            return "SOAR 보안 도구 실행 실패, 수동 확인이 필요합니다: " + error.getMessage();
        }
        
        return "도구 실행 실패: " + error.getMessage();
    }

    private void logIntegrationStatus() {
        UnifiedIntegrationStats stats = getUnifiedIntegrationStats();

        Map<SoarTool.RiskLevel, Long> riskDistribution = unifiedTools.values().stream()
            .collect(java.util.stream.Collectors.groupingBy(
                EnhancedToolCallback::getRiskLevel,
                java.util.stream.Collectors.counting()
            ));
        
                riskDistribution.forEach((level, count) -> {
                    });
    }

    public static class ToolExecutionStats {
        private final String toolName;
        private long totalExecutions = 0;
        private long successfulExecutions = 0;
        private long totalExecutionTime = 0;
        private long lastExecutionTime = 0;
        
        public ToolExecutionStats(String toolName) {
            this.toolName = toolName;
        }
        
        public synchronized void recordExecution(long executionTime, boolean success) {
            totalExecutions++;
            totalExecutionTime += executionTime;
            lastExecutionTime = System.currentTimeMillis();
            
            if (success) {
                successfulExecutions++;
            }
        }
        
        public String getToolName() { return toolName; }
        public long getTotalExecutions() { return totalExecutions; }
        public long getSuccessfulExecutions() { return successfulExecutions; }
        public double getSuccessRate() { 
            return totalExecutions > 0 ? (double) successfulExecutions / totalExecutions : 0.0; 
        }
        public double getAverageExecutionTime() { 
            return totalExecutions > 0 ? (double) totalExecutionTime / totalExecutions : 0.0; 
        }
        public long getLastExecutionTime() { return lastExecutionTime; }
    }

    public record UnifiedIntegrationStats(
        int soarToolCount,
        int mcpToolCount,
        int totalToolCount,
        long totalExecutions,
        boolean mcpEnabled,
        long lastUpdateTime
    ) {}
}