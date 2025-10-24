package io.contexa.contexacore.mcp.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.mcp.SyncMcpToolCallback;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * MCP Function Callback Provider - Spring AI 표준 구현
 * 
 * MCP 클라이언트의 도구들을 Spring AI 표준 ToolCallback으로 변환하여 제공합니다.
 * SyncMcpToolCallback을 사용하여 표준을 완벽하게 준수하며,
 * prefix 없이 원본 도구 이름을 사용하고 메타데이터로 출처를 구분합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = false)
public class McpFunctionCallbackProvider {
    
    private final McpSyncClient braveSearchMcpClient;
    private final McpSyncClient securityMcpClient;
    private final Map<String, ToolCallback> toolCallbacks = new ConcurrentHashMap<>();
    private final Map<String, String> toolClientMapping = new ConcurrentHashMap<>();  // 도구명 -> 클라이언트 매핑
    
    /**
     * MCP 도구들을 Spring AI 표준 ToolCallback 배열로 반환
     * prefix 없는 원본 이름으로 반환됩니다.
     */
    public ToolCallback[] getMcpToolCallbacks() {
        initializeMcpCallbacks();
        return toolCallbacks.values().toArray(new ToolCallback[0]);
    }
    
    /**
     * 모든 MCP 도구 목록 반환 (이름과 메타데이터 포함)
     */
    public List<Map<String, Object>> getAllToolsWithMetadata() {
        initializeMcpCallbacks();
        
        return toolCallbacks.entrySet().stream()
            .map(entry -> {
                Map<String, Object> toolInfo = new HashMap<>();
                toolInfo.put("name", entry.getKey());
                toolInfo.put("client", toolClientMapping.get(entry.getKey()));
                toolInfo.put("definition", entry.getValue().getToolDefinition());
                return toolInfo;
            })
            .collect(Collectors.toList());
    }
    
    /**
     * 특정 MCP 도구 가져오기 (prefix 없는 원본 이름으로 검색)
     */
    public Optional<ToolCallback> getMcpToolCallback(String name) {
        initializeMcpCallbacks();
        return Optional.ofNullable(toolCallbacks.get(name));
    }
    
    /**
     * 클라이언트별로 도구 검색
     */
    public List<ToolCallback> getToolsByClient(String clientName) {
        initializeMcpCallbacks();
        
        return toolClientMapping.entrySet().stream()
            .filter(entry -> clientName.equals(entry.getValue()))
            .map(entry -> toolCallbacks.get(entry.getKey()))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    /**
     * MCP Callback 초기화 - Spring AI 표준 방식
     */
    private synchronized void initializeMcpCallbacks() {
        if (!toolCallbacks.isEmpty()) {
            return; // 이미 초기화됨
        }
        
        log.info("Spring AI 표준 MCP Function Callback 초기화 시작");
        
        // Brave Search MCP 클라이언트 도구 등록
        if (braveSearchMcpClient != null) {
            registerMcpClientTools("brave-search", braveSearchMcpClient);
        }
        
        // Security MCP 클라이언트 도구 등록
        if (securityMcpClient != null) {
            registerMcpClientTools("security", securityMcpClient);
        }
        
        log.info("Spring AI 표준 MCP Function Callback 초기화 완료: {} 개 도구", toolCallbacks.size());
        logInitializationSummary();
    }
    
    /**
     * 초기화 요약 로깅
     */
    private void logInitializationSummary() {
        Map<String, Long> clientCounts = toolClientMapping.values().stream()
            .collect(Collectors.groupingBy(client -> client, Collectors.counting()));
        
        log.info("MCP 도구 초기화 요약:");
        clientCounts.forEach((client, count) -> 
            log.info("  - {} 클라이언트: {} 개 도구", client, count)
        );
    }
    
    /**
     * MCP 클라이언트의 도구들을 Spring AI 표준 방식으로 등록
     * prefix 없이 원본 도구 이름을 사용합니다.
     */
    private void registerMcpClientTools(String clientName, McpSyncClient mcpClient) {
        try {
            log.info("{} MCP 클라이언트 도구 등록 시작", clientName);

            var toolsResult = mcpClient.listTools(null);
            if (toolsResult != null && toolsResult.tools() != null) {
                int registeredCount = 0;
                
                for (McpSchema.Tool tool : toolsResult.tools()) {
                    try {
                        // prefix 없는 원본 도구 이름 사용
                        String toolName = tool.name();
                        
                        // 도구 이름 충돌 처리 - 기존 도구가 있으면 건너뜀
                        if (toolCallbacks.containsKey(toolName)) {
                            log.debug("⏭️ 도구 이름 충돌 감지: {}. 기존 도구 유지, 새 도구 건너뜀", toolName);
                            continue; // 기존 도구를 유지하고 새 도구는 등록하지 않음
                        }
                        
                        // Spring AI가 제공하는 SyncMcpToolCallback 사용
                        ToolCallback callback = new SyncMcpToolCallback(mcpClient, tool);
                        
                        // 도구 등록
                        toolCallbacks.put(toolName, callback);
                        toolClientMapping.put(toolName, clientName);
                        
                        log.debug("✓ 도구 등록: {} - {} (클라이언트: {})", 
                                 toolName, tool.description(), clientName);
                        registeredCount++;
                        
                    } catch (Exception e) {
                        log.error("도구 등록 실패: {} - {}", tool.name(), e.getMessage(), e);
                    }
                }

                log.info("{} MCP 클라이언트 도구 등록 완료: {} 개",
                        clientName, registeredCount);
            } else {
                log.warn("{} MCP 클라이언트에서 도구를 찾을 수 없음", clientName);
            }

        } catch (Exception e) {
            log.error("{} MCP 클라이언트 도구 등록 실패: {}", clientName, e.getMessage(), e);
        }
    }
    // 내부 클래스 McpToolCallback 제거됨 - SyncMcpToolCallback 사용
    
    /**
     * MCP 도구 통계 정보 - 향상된 버전
     */
    public Map<String, Object> getMcpToolStatistics() {
        initializeMcpCallbacks();
        
        Map<String, Long> clientCounts = toolClientMapping.values().stream()
            .collect(Collectors.groupingBy(client -> client, Collectors.counting()));
        
        Map<String, Object> statistics = new HashMap<>();
        statistics.put("total", toolCallbacks.size());
        statistics.put("byClient", clientCounts);
        statistics.put("clients", new HashSet<>(toolClientMapping.values()));
        statistics.put("toolNames", new HashSet<>(toolCallbacks.keySet()));
        statistics.put("initialized", !toolCallbacks.isEmpty());
        
        return statistics;
    }
    
    // ========== MCP Resources 지원 추가 ==========
    
    private final Map<String, McpResource> mcpResources = new ConcurrentHashMap<>();
    
    /**
     * MCP 리소스들을 가져오기
     */
    public Map<String, McpResource> getMcpResources() {
        initializeMcpResources();
        return new HashMap<>(mcpResources);
    }
    
    /**
     * MCP Resources 초기화
     */
    private void initializeMcpResources() {
        if (!mcpResources.isEmpty()) {
            return; // 이미 초기화됨
        }
        
        log.info("📚 MCP Resources 초기화 시작");
        
        // Security MCP 클라이언트 리소스 등록
        if (securityMcpClient != null) {
            registerMcpClientResources("security", securityMcpClient);
        }
        
        log.info("MCP Resources 초기화 완료: {} 개", mcpResources.size());
    }
    
    /**
     * MCP 클라이언트의 리소스들을 등록
     */
    private void registerMcpClientResources(String clientName, McpSyncClient mcpClient) {
        try {
            log.info("📖 {} MCP 클라이언트 리소스 등록 시작", clientName);
            
            var resourcesResult = mcpClient.listResources(null);
            if (resourcesResult != null && resourcesResult.resources() != null) {
                resourcesResult.resources().forEach(resource -> {
                    String resourceName = String.format("%s_%s", clientName, resource.name());
                    McpResource mcpResource = new McpResource(resourceName, resource, mcpClient);
                    mcpResources.put(resourceName, mcpResource);
                    
                    log.debug("리소스 등록: {} - {}", resourceName, resource.description());
                });
                
                log.info("{} MCP 클라이언트 리소스 등록 완료: {} 개", 
                        clientName, resourcesResult.resources().size());
            }
            
        } catch (Exception e) {
            log.warn("{} MCP 클라이언트 리소스 등록 실패: {}", clientName, e.getMessage());
        }
    }
    
    /**
     * MCP Resource를 래핑하는 구현체
     */
    public static class McpResource {
        private final String name;
        private final McpSchema.Resource mcpResource;
        private final McpSyncClient mcpClient;
        
        public McpResource(String name, McpSchema.Resource mcpResource, McpSyncClient mcpClient) {
            this.name = name;
            this.mcpResource = mcpResource;
            this.mcpClient = mcpClient;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return mcpResource.description() != null ? mcpResource.description() : "MCP Resource: " + name;
        }
        
        /**
         * 리소스 내용 읽기
         */
        public String readResource() {
            try {
                log.debug("📖 MCP Resource 읽기: {}", name);
                
                var readResult = mcpClient.readResource(
                    new McpSchema.ReadResourceRequest(mcpResource.uri())
                );
                
                if (readResult != null && readResult.contents() != null && !readResult.contents().isEmpty()) {
                    var content = readResult.contents().get(0);
                    if (content instanceof McpSchema.TextResourceContents textContent) {
                        return textContent.text();
                    } else if (content instanceof McpSchema.BlobResourceContents blobContent) {
                        return "Binary data: " + blobContent.blob();
                    }
                }
                
                return "리소스 내용 없음";
                
            } catch (Exception e) {
                log.error("MCP Resource 읽기 실패: {} - {}", name, e.getMessage());
                return "오류: " + e.getMessage();
            }
        }
    }

    // ========== MCP Prompts 지원 추가 ==========

    private final Map<String, McpPrompt> mcpPrompts = new ConcurrentHashMap<>();

    /**
     * MCP 프롬프트들을 가져오기
     */
    public Map<String, McpPrompt> getMcpPrompts() {
        initializeMcpPrompts();
        return new HashMap<>(mcpPrompts);
    }

    /**
     * MCP Prompts 초기화
     */
    private void initializeMcpPrompts() {
        if (!mcpPrompts.isEmpty()) {
            return; // 이미 초기화됨
        }

        log.info("MCP Prompts 초기화 시작");

        // Security MCP 클라이언트 프롬프트 등록
        if (securityMcpClient != null) {
            registerMcpClientPrompts("security", securityMcpClient);
        }

        log.info("MCP Prompts 초기화 완료: {} 개", mcpPrompts.size());
    }

    /**
     * MCP 클라이언트의 프롬프트들을 등록
     */
    private void registerMcpClientPrompts(String clientName, McpSyncClient mcpClient) {
        try {
            log.info("💭 {} MCP 클라이언트 프롬프트 등록 시작", clientName);

            var promptsResult = mcpClient.listPrompts(null);
            if (promptsResult != null && promptsResult.prompts() != null) {
                promptsResult.prompts().forEach(prompt -> {
                    String promptName = String.format("%s_%s", clientName, prompt.name());
                    McpPrompt mcpPrompt = new McpPrompt(promptName, prompt, mcpClient);
                    mcpPrompts.put(promptName, mcpPrompt);

                    log.debug("프롬프트 등록: {} - {}", promptName, prompt.description());
                });

                log.info("{} MCP 클라이언트 프롬프트 등록 완료: {} 개",
                        clientName, promptsResult.prompts().size());
            }

        } catch (Exception e) {
            log.warn("{} MCP 클라이언트 프롬프트 등록 실패: {}", clientName, e.getMessage());
        }
    }

    /**
     * MCP Prompt를 래핑하는 구현체
     */
    public static class McpPrompt {
        private final String name;
        private final McpSchema.Prompt mcpPrompt;
        private final McpSyncClient mcpClient;

        public McpPrompt(String name, McpSchema.Prompt mcpPrompt, McpSyncClient mcpClient) {
            this.name = name;
            this.mcpPrompt = mcpPrompt;
            this.mcpClient = mcpClient;
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return mcpPrompt.description() != null ? mcpPrompt.description() : "MCP Prompt: " + name;
        }

        /**
         * 프롬프트 메시지 가져오기
         */
        public String getPromptMessage(Map<String, Object> arguments) {
            try {
                log.debug("MCP Prompt 가져오기: {} - 인수: {}", name, arguments);

                var getResult = mcpClient.getPrompt(
                    new McpSchema.GetPromptRequest(mcpPrompt.name(), arguments != null ? arguments : Map.of())
                );

                if (getResult != null && getResult.messages() != null && !getResult.messages().isEmpty()) {
                    StringBuilder promptBuilder = new StringBuilder();

                    for (var message : getResult.messages()) {
                        if (message.role() != null) {
                            promptBuilder.append("[").append(message.role()).append("]:\n");
                        }

                        if (message.content() instanceof McpSchema.TextContent textContent) {
                            promptBuilder.append(textContent.text()).append("\n\n");
                        } else if (message.content() instanceof McpSchema.ImageContent imageContent) {
                            promptBuilder.append("이미지: ").append(imageContent.data()).append("\n\n");
                        }
                    }

                    return promptBuilder.toString().trim();
                }

                return "프롬프트 메시지 없음";

            } catch (Exception e) {
                log.error("MCP Prompt 가져오기 실패: {} - {}", name, e.getMessage());
                return "오류: " + e.getMessage();
            }
        }
    }
}