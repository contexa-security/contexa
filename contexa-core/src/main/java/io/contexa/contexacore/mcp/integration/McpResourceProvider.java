package io.contexa.contexacore.mcp.integration;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * MCP Resource Provider
 * 
 * MCP 클라이언트의 리소스들을 관리하고 제공합니다.
 * Resources는 MCP 서버가 노출하는 읽기 전용 데이터 소스입니다.
 * 
 * 주요 기능:
 * - 보안 정책 템플릿 제공
 * - 위협 인텔리전스 데이터 제공
 * - 컴플라이언스 가이드라인 제공
 * - 시스템 구성 정보 제공
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = false)
public class McpResourceProvider {
    
    private final McpSyncClient braveSearchMcpClient;
    private final McpSyncClient securityMcpClient;
    private final Map<String, ResourceWrapper> resources = new ConcurrentHashMap<>();
    
    /**
     * 모든 사용 가능한 리소스 목록 반환
     */
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
    
    /**
     * 특정 리소스 읽기
     */
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
    
    /**
     * 카테고리별 리소스 검색
     */
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
    
    /**
     * 리소스 초기화
     */
    private void initializeResources() {
        if (!resources.isEmpty()) {
            return; // 이미 초기화됨
        }
        
        log.info("📚 MCP Resources Provider 초기화 시작");
        
        // Brave Search MCP 클라이언트 리소스 등록
        if (braveSearchMcpClient != null) {
            registerClientResources("brave-search", braveSearchMcpClient);
        }
        
        // Security MCP 클라이언트 리소스 등록
        if (securityMcpClient != null) {
            registerClientResources("security", securityMcpClient);
        }
        
        log.info("MCP Resources Provider 초기화 완료: {} 개 리소스", resources.size());
    }
    
    /**
     * MCP 클라이언트의 리소스들을 등록
     */
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
    
    /**
     * 리소스 정보 DTO
     */
    public record ResourceInfo(
        String name,
        String uri,
        String description,
        String mimeType,
        String clientName
    ) {}
    
    /**
     * 리소스 래퍼 클래스
     */
    private static class ResourceWrapper {
        private final String name;
        private final McpSchema.Resource resource;
        private final McpSyncClient client;
        private final String clientName;
        private String cachedContent;
        private long cacheTime;
        private static final long CACHE_DURATION = 5 * 60 * 1000; // 5분
        
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
        
        /**
         * 리소스 내용 읽기 (캐싱 포함)
         */
        public String read() {
            // 캐시 확인
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
        
        /**
         * 카테고리 매칭 확인
         */
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
    
    /**
     * 리소스 통계 정보
     */
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