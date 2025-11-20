package io.contexa.contexacoreenterprise.mcp.tool.provider;

import io.modelcontextprotocol.client.McpSyncClient;
import org.springframework.ai.tool.ToolCallback;

import java.util.Map;
import java.util.Optional;

/**
 * McpClientProvider 인터페이스
 * 
 * MCP 클라이언트를 관리하고 제공하는 인터페이스입니다.
 */
public interface McpClientProvider {
    
    /**
     * 특정 서버의 MCP 클라이언트 가져오기
     * 
     * @param serverName 서버 이름 (예: "brave-search", "security")
     * @return MCP 클라이언트 (없으면 empty)
     */
    Optional<McpSyncClient> getClient(String serverName);
    
    /**
     * 모든 MCP 클라이언트 가져오기
     * 
     * @return 서버 이름과 클라이언트 매핑
     */
    Map<String, McpSyncClient> getAllClients();
    
    /**
     * 특정 서버의 클라이언트가 있는지 확인
     * 
     * @param serverName 서버 이름
     * @return 클라이언트 존재 여부
     */
    boolean hasClient(String serverName);
    
    /**
     * MCP 도구 콜백 배열 반환
     * 
     * @return ToolCallback 배열
     */
    default ToolCallback[] getToolCallbacks() {
        // 기본 구현: 빈 배열 반환
        return new ToolCallback[0];
    }
    
    /**
     * MCP 서버 연결 상태 확인
     * 
     * @return 연결 상태
     */
    default boolean isConnected() {
        return !getAllClients().isEmpty();
    }
    
    /**
     * MCP 서버 정보 반환
     * 
     * @return 서버 정보 문자열
     */
    default String getServerInfo() {
        Map<String, McpSyncClient> clients = getAllClients();
        return "MCP Servers: " + clients.keySet();
    }
}