package io.contexa.contexacoreenterprise.mcp.integration;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class McpResourceProvider {
    
    private final McpSyncClient braveSearchMcpClient;
    private final McpSyncClient securityMcpClient;
    private final Map<String, ResourceWrapper> resources = new ConcurrentHashMap<>();
    
    
    public List<ResourceInfo> listAvailableResources() {
        initializeResources();
        
        return resources.values().stream()
            .map(wrapper -> new ResourceInfo(
                wrapper.getName(),
                wrapper.getUri(),
                wrapper.getDescription(),
                wrapper.getMimeType(),
                wrapper.getClientName()
            ))
            .collect(Collectors.toList());
    }
    
    
    public Optional<String> readResource(String resourceName) {
        initializeResources();
        
        ResourceWrapper wrapper = resources.get(resourceName);
        if (wrapper == null) {
            log.warn("리소스를 찾을 수 없음: {}", resourceName);
            return Optional.empty();
        }
        
        try {
            return Optional.of(wrapper.read());
        } catch (Exception e) {
            log.error("리소스 읽기 실패: {} - {}", resourceName, e.getMessage());
            return Optional.empty();
        }
    }
    
    
    public List<ResourceInfo> findResourcesByCategory(String category) {
        initializeResources();
        
        return resources.values().stream()
            .filter(wrapper -> wrapper.matchesCategory(category))
            .map(wrapper -> new ResourceInfo(
                wrapper.getName(),
                wrapper.getUri(),
                wrapper.getDescription(),
                wrapper.getMimeType(),
                wrapper.getClientName()
            ))
            .collect(Collectors.toList());
    }
    
    
    private void initializeResources() {
        if (!resources.isEmpty()) {
            return; 
        }
        
        log.info("📚 MCP Resources Provider 초기화 시작");
        
        
        if (braveSearchMcpClient != null) {
            registerClientResources("brave-search", braveSearchMcpClient);
        }
        
        
        if (securityMcpClient != null) {
            registerClientResources("security", securityMcpClient);
        }
        
        log.info("MCP Resources Provider 초기화 완료: {} 개 리소스", resources.size());
    }
    
    
    private void registerClientResources(String clientName, McpSyncClient mcpClient) {
        try {
            log.info("📖 {} MCP 클라이언트 리소스 등록 시작", clientName);
            
            var listResult = mcpClient.listResources(null);
            if (listResult != null && listResult.resources() != null) {
                for (var resource : listResult.resources()) {
                    String fullName = String.format("%s_%s", clientName, resource.name());
                    ResourceWrapper wrapper = new ResourceWrapper(
                        fullName,
                        resource,
                        mcpClient,
                        clientName
                    );
                    resources.put(fullName, wrapper);
                    
                    log.debug("리소스 등록: {} - {}", fullName, resource.description());
                }
                
                log.info("{} MCP 클라이언트 리소스 등록 완료: {} 개", 
                        clientName, listResult.resources().size());
            }
        } catch (Exception e) {
            log.warn("{} MCP 클라이언트 리소스 등록 실패: {}", clientName, e.getMessage());
        }
    }
    
    
    public record ResourceInfo(
        String name,
        String uri,
        String description,
        String mimeType,
        String clientName
    ) {}
    
    
    private static class ResourceWrapper {
        private final String name;
        private final McpSchema.Resource resource;
        private final McpSyncClient client;
        private final String clientName;
        private String cachedContent;
        private long cacheTime;
        private static final long CACHE_DURATION = 5 * 60 * 1000; 
        
        public ResourceWrapper(String name, McpSchema.Resource resource, 
                              McpSyncClient client, String clientName) {
            this.name = name;
            this.resource = resource;
            this.client = client;
            this.clientName = clientName;
        }
        
        public String getName() {
            return name;
        }
        
        public String getUri() {
            return resource.uri();
        }
        
        public String getDescription() {
            return resource.description() != null ? 
                resource.description() : "MCP Resource: " + name;
        }
        
        public String getMimeType() {
            return resource.mimeType() != null ? 
                resource.mimeType() : "text/plain";
        }
        
        public String getClientName() {
            return clientName;
        }
        
        
        public String read() {
            
            if (cachedContent != null && 
                (System.currentTimeMillis() - cacheTime) < CACHE_DURATION) {
                log.debug("캐시된 리소스 반환: {}", name);
                return cachedContent;
            }
            
            try {
                log.debug("📖 MCP Resource 읽기: {}", name);
                
                var readResult = client.readResource(
                    new McpSchema.ReadResourceRequest(resource.uri())
                );
                
                if (readResult != null && readResult.contents() != null) {
                    StringBuilder contentBuilder = new StringBuilder();
                    
                    for (var content : readResult.contents()) {
                        if (content instanceof McpSchema.TextResourceContents textContent) {
                            contentBuilder.append(textContent.text());
                        } else if (content instanceof McpSchema.BlobResourceContents blobContent) {
                            contentBuilder.append("Binary data: ").append(blobContent.blob());
                        }
                    }
                    
                    cachedContent = contentBuilder.toString();
                    cacheTime = System.currentTimeMillis();
                    return cachedContent;
                }
                
                return "리소스 내용 없음";
                
            } catch (Exception e) {
                log.error("MCP Resource 읽기 실패: {} - {}", name, e.getMessage());
                throw new RuntimeException("리소스 읽기 실패: " + e.getMessage(), e);
            }
        }
        
        
        public boolean matchesCategory(String category) {
            if (category == null || category.isEmpty()) {
                return true;
            }
            
            String lowerCategory = category.toLowerCase();
            String lowerName = name.toLowerCase();
            String lowerDesc = getDescription().toLowerCase();
            
            return lowerName.contains(lowerCategory) || 
                   lowerDesc.contains(lowerCategory);
        }
    }
    
    
    public Map<String, Object> getResourceStatistics() {
        initializeResources();
        
        Map<String, Integer> clientCounts = new HashMap<>();
        Map<String, List<String>> resourcesByClient = new HashMap<>();
        
        for (ResourceWrapper wrapper : resources.values()) {
            String client = wrapper.getClientName();
            clientCounts.merge(client, 1, Integer::sum);
            resourcesByClient.computeIfAbsent(client, k -> new ArrayList<>())
                            .add(wrapper.getName());
        }
        
        return Map.of(
            "total", resources.size(),
            "byClient", clientCounts,
            "resources", resourcesByClient
        );
    }
}