package io.contexa.contexacoreenterprise.mcp.tool.provider;

import io.modelcontextprotocol.client.McpSyncClient;
import org.springframework.ai.tool.ToolCallback;

import java.util.Map;
import java.util.Optional;

public interface McpClientProvider {

    Optional<McpSyncClient> getClient(String serverName);

    Map<String, McpSyncClient> getAllClients();

    boolean hasClient(String serverName);

    default ToolCallback[] getToolCallbacks() {
        
        return new ToolCallback[0];
    }

    default boolean isConnected() {
        return !getAllClients().isEmpty();
    }

    default String getServerInfo() {
        Map<String, McpSyncClient> clients = getAllClients();
        return "MCP Servers: " + clients.keySet();
    }
}