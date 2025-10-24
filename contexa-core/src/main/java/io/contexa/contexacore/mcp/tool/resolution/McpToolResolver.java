package io.contexa.contexacore.mcp.tool.resolution;

import io.contexa.contexacore.mcp.integration.McpFunctionCallbackProvider;
import io.contexa.contexacore.mcp.tool.provider.McpClientProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * McpToolResolver
 * 
 * MCP (Model Context Protocol) 서버에서 원격 도구를 해결합니다.
 * MCP 클라이언트를 통해 연결된 서버의 도구들을 검색합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class McpToolResolver implements ToolCallbackResolver {
    
    private final McpClientProvider mcpProvider;
    private final McpFunctionCallbackProvider mcpFunctionCallbackProvider;

    @Override
    public ToolCallback resolve(String toolName) {

        log.trace("MCP 도구 검색: {}", toolName);
        
        // JavaSDKMCPClient_ prefix 제거 (Spring AI가 자동으로 붙이는 경우 처리)
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
    
    /**
     * MCP 컨텍스트 래퍼 적용
     */
    private ToolCallback wrapWithMcpContext(ToolCallback tool) {
        return new McpContextAwareToolCallback(tool, mcpProvider);
    }
    
    /**
     * MCP 서버 연결 상태 확인
     */
    public boolean isConnected() {
        return mcpProvider != null && mcpProvider.isConnected();
    }
    
    /**
     * 모든 MCP 도구 반환
     */
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
    
    /**
     * MCP 도구 통계
     */
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
    
    /**
     * MCP 컨텍스트가 적용된 도구 콜백 래퍼
     */
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
            // MCP 컨텍스트 확인
            if (!provider.isConnected()) {
                throw new McpConnectionException("MCP 서버 연결이 끊어짐");
            }
            
            log.trace("MCP 도구 호출: {} via {}", 
                delegate.getToolDefinition().name(),
                provider.getServerInfo());
            
            return delegate.call(arguments);
        }
    }
    
    /**
     * MCP 연결 예외
     */
    public static class McpConnectionException extends RuntimeException {
        public McpConnectionException(String message) {
            super(message);
        }
    }
    
    /**
     * MCP 도구 통계 레코드
     */
    public record McpToolStatistics(
        boolean connected,
        int toolCount,
        String serverInfo
    ) {}
}