package io.contexa.contexacoreenterprise.mcp.integration;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;


@Slf4j
@RequiredArgsConstructor
public class McpToolIntegrationAdapter implements ToolIntegrationProvider {
    
    private final McpFunctionCallbackProvider mcpProvider;
    
    
    @Override
    public ToolCallback[] getToolCallbacks() {
        try {
            return mcpProvider.getMcpToolCallbacks();
        } catch (Exception e) {
            log.warn("MCP 도구 가져오기 실패: {}", e.getMessage());
            return new ToolCallback[0];
        }
    }
    
    
    @Override
    public Optional<ToolCallback> getToolCallback(String name) {
        try {
            ToolCallback[] callbacks = getToolCallbacks();
            for (ToolCallback callback : callbacks) {
                if (callback.getToolDefinition().name().equals(name)) {
                    return Optional.of(callback);
                }
            }
        } catch (Exception e) {
            log.warn("MCP 도구 {} 조회 실패: {}", name, e.getMessage());
        }
        return Optional.empty();
    }
    
    
    @Override
    public SoarTool.RiskLevel getToolRiskLevel(String name) {
        
        
        if (name != null) {
            if (name.contains("delete") || name.contains("remove")) {
                return SoarTool.RiskLevel.MEDIUM;
            }
            if (name.contains("search") || name.contains("query")) {
                return SoarTool.RiskLevel.LOW;
            }
        }
        return SoarTool.RiskLevel.LOW;
    }
    
    
    @Override
    public boolean requiresApproval(String name) {
        
        
        SoarTool.RiskLevel riskLevel = getToolRiskLevel(name);
        return riskLevel == SoarTool.RiskLevel.HIGH || 
               riskLevel == SoarTool.RiskLevel.CRITICAL;
    }
    
    
    @Override
    public Set<String> getRegisteredToolNames() {
        Set<String> names = new HashSet<>();
        try {
            ToolCallback[] callbacks = getToolCallbacks();
            for (ToolCallback callback : callbacks) {
                names.add(callback.getToolDefinition().name());
            }
        } catch (Exception e) {
            log.warn("MCP 도구 이름 목록 조회 실패: {}", e.getMessage());
        }
        return names;
    }
    
    
    @Override
    public String getProviderType() {
        return "MCP";
    }
    
    
    @Override
    public boolean isReady() {
        try {
            return mcpProvider != null && getToolCallbacks().length > 0;
        } catch (Exception e) {
            return false;
        }
    }
}