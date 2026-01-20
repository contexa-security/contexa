package io.contexa.contexacoreenterprise.mcp.tool.provider;

import io.modelcontextprotocol.client.McpSyncClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


@Primary
@Slf4j
public class McpClientProviderImpl implements McpClientProvider {
    
    private final Map<String, McpSyncClient> clients = new HashMap<>();
    
    @Autowired(required = false)
    public McpClientProviderImpl(List<McpSyncClient> mcpClients,
                                @Autowired(required = false) McpSyncClient braveSearchMcpClient,
                                @Autowired(required = false) McpSyncClient securityMcpClient) {
        
        
        if (braveSearchMcpClient != null) {
            clients.put("brave-search", braveSearchMcpClient);
            log.info("MCP 클라이언트 등록: brave-search");
        }
        
        if (securityMcpClient != null) {
            clients.put("security", securityMcpClient);
            log.info("MCP 클라이언트 등록: security");
        }
        
        
        if (mcpClients != null) {
            for (int i = 0; i < mcpClients.size(); i++) {
                McpSyncClient client = mcpClients.get(i);
                if (!clients.containsValue(client)) {
                    String name = "mcp-client-" + i;
                    clients.put(name, client);
                    log.info("MCP 클라이언트 등록: {}", name);
                }
            }
        }
        
        log.info("McpClientProviderImpl 초기화 완료: {} 개의 클라이언트", clients.size());
    }
    
    @Override
    public Optional<McpSyncClient> getClient(String serverName) {
        return Optional.ofNullable(clients.get(serverName));
    }
    
    @Override
    public Map<String, McpSyncClient> getAllClients() {
        return new HashMap<>(clients);
    }
    
    @Override
    public boolean hasClient(String serverName) {
        return clients.containsKey(serverName);
    }
    
    
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalClients", clients.size());
        stats.put("clientNames", clients.keySet());
        
        Map<String, String> clientStatus = new HashMap<>();
        for (Map.Entry<String, McpSyncClient> entry : clients.entrySet()) {
            clientStatus.put(entry.getKey(), entry.getValue() != null ? "active" : "inactive");
        }
        stats.put("clientStatus", clientStatus);
        
        return stats;
    }
}