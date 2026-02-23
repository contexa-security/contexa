package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import io.contexa.contexacoreenterprise.mcp.integration.McpFunctionCallbackProvider;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class McpToolResolver implements ToolCallbackResolver {

    public static final String MCP_CLIENT_PREFIX = "JavaSDKMCPClient_";

    private final McpClientProvider mcpProvider;
    private final McpFunctionCallbackProvider mcpFunctionCallbackProvider;

    @Override
    public ToolCallback resolve(String toolName) {

        String actualToolName = toolName;
        if (toolName.startsWith(MCP_CLIENT_PREFIX)) {
            actualToolName = toolName.substring(MCP_CLIENT_PREFIX.length());
                    }
        
        try {
            ToolCallback tool = mcpFunctionCallbackProvider.getMcpToolCallback(actualToolName).orElse(null);
            if (tool == null) {
                log.error("MCP tool not found: {}", actualToolName);
                return null;
            }
            return wrapWithMcpContext(tool);

        } catch (Exception e) {
            log.error("MCP tool search failed: {} - {}", actualToolName, e.getMessage());
            return null;
        }
    }

    private ToolCallback wrapWithMcpContext(ToolCallback tool) {
        return new McpContextAwareToolCallback(tool, mcpProvider);
    }

    public boolean isConnected() {
        return mcpProvider != null && mcpProvider.isConnected();
    }

    public List<ToolCallback> getAllTools() {
        if (!isConnected()) {
            return List.of();
        }
        
        try {
            ToolCallback[] tools = mcpFunctionCallbackProvider.getMcpToolCallbacks();
            return Arrays.asList(tools);
        } catch (Exception e) {
            log.error("Failed to fetch MCP tool list: {}", e.getMessage());
            return List.of();
        }
    }

    public McpToolStatistics getStatistics() {
        if (!isConnected()) {
            return new McpToolStatistics(false, 0, null);
        }

        var tools = getAllTools();
        var serverInfo = mcpProvider.getServerInfo();

        return new McpToolStatistics(
            true,
            tools.size(),
            serverInfo
        );
    }

    private static class McpContextAwareToolCallback implements ToolCallback {
        private final ToolCallback delegate;
        private final McpClientProvider provider;
        
        public McpContextAwareToolCallback(ToolCallback delegate, McpClientProvider provider) {
            this.delegate = delegate;
            this.provider = provider;
        }
        
        @Override
        public org.springframework.ai.tool.definition.ToolDefinition getToolDefinition() {
            return delegate.getToolDefinition();
        }
        
        @Override
        public String call(String arguments) {
            
            if (!provider.isConnected()) {
                throw new McpConnectionException("MCP server connection lost");
            }

            return delegate.call(arguments);
        }
    }

    public static class McpConnectionException extends RuntimeException {
        public McpConnectionException(String message) {
            super(message);
        }
    }

    public record McpToolStatistics(
        boolean connected,
        int toolCount,
        String serverInfo
    ) {}
}