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
    
    private final McpClientProvider mcpProvider;
    private final McpFunctionCallbackProvider mcpFunctionCallbackProvider;

    @Override
    public ToolCallback resolve(String toolName) {

        log.trace("MCP 도구 검색: {}", toolName);
        
        
        String actualToolName = toolName;
        if (toolName != null && toolName.startsWith("JavaSDKMCPClient_")) {
            actualToolName = toolName.substring("JavaSDKMCPClient_".length());
            log.debug("MCP 도구 이름 변환: {} -> {}", toolName, actualToolName);
        }
        
        try {
            ToolCallback tool = mcpFunctionCallbackProvider.getMcpToolCallback(actualToolName).orElse(null);
            return wrapWithMcpContext(tool);

        } catch (Exception e) {
            log.warn("MCP 도구 검색 실패: {} - {}", actualToolName, e.getMessage());
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
            log.warn("MCP 도구 목록 가져오기 실패: {}", e.getMessage());
            return List.of();
        }
    }
    
    
    public McpToolStatistics getStatistics() {
        if (!isConnected()) {
            return new McpToolStatistics(false, 0, null);
        }
        
        var tools = mcpProvider.getToolCallbacks();
        var serverInfo = mcpProvider.getServerInfo();
        
        return new McpToolStatistics(
            true,
            tools.length,
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
                throw new McpConnectionException("MCP 서버 연결이 끊어짐");
            }
            
            log.trace("MCP 도구 호출: {} via {}", 
                delegate.getToolDefinition().name(),
                provider.getServerInfo());
            
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