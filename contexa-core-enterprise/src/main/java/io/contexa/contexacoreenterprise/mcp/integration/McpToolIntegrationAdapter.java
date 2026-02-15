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
            log.error("Failed to get MCP tools: {}", e.getMessage());
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
            log.error("Failed to get MCP tool {}: {}", name, e.getMessage());
        }
        return Optional.empty();
    }

    @Override
    public SoarTool.RiskLevel getToolRiskLevel(String name) {
        if (name != null) {
            String lower = name.toLowerCase();
            if (lower.contains("destroy") || lower.contains("terminate") || lower.contains("wipe")) {
                return SoarTool.RiskLevel.CRITICAL;
            }
            if (lower.contains("block") || lower.contains("isolate") ||
                lower.contains("shutdown") || lower.contains("kill")) {
                return SoarTool.RiskLevel.HIGH;
            }
            if (lower.contains("delete") || lower.contains("remove") ||
                lower.contains("modify") || lower.contains("update") || lower.contains("execute")) {
                return SoarTool.RiskLevel.MEDIUM;
            }
            if (lower.contains("search") || lower.contains("query")) {
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
            log.error("Failed to get MCP tool names: {}", e.getMessage());
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