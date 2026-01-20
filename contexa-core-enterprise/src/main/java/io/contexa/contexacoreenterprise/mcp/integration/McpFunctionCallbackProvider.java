package io.contexa.contexacoreenterprise.mcp.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.mcp.SyncMcpToolCallback;
import org.springframework.ai.tool.ToolCallback;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class McpFunctionCallbackProvider {
    
    private final McpSyncClient braveSearchMcpClient;
    private final McpSyncClient securityMcpClient;
    private final Map<String, ToolCallback> toolCallbacks = new ConcurrentHashMap<>();
    private final Map<String, String> toolClientMapping = new ConcurrentHashMap<>();  
    
    
    public ToolCallback[] getMcpToolCallbacks() {
        initializeMcpCallbacks();
        return toolCallbacks.values().toArray(new ToolCallback[0]);
    }
    
    
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
    
    
    public Optional<ToolCallback> getMcpToolCallback(String name) {
        initializeMcpCallbacks();
        return Optional.ofNullable(toolCallbacks.get(name));
    }
    
    
    public List<ToolCallback> getToolsByClient(String clientName) {
        initializeMcpCallbacks();
        
        return toolClientMapping.entrySet().stream()
            .filter(entry -> clientName.equals(entry.getValue()))
            .map(entry -> toolCallbacks.get(entry.getKey()))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    
    private synchronized void initializeMcpCallbacks() {
        if (!toolCallbacks.isEmpty()) {
            return; 
        }
        
        log.info("Spring AI 표준 MCP Function Callback 초기화 시작");
        
        
        if (braveSearchMcpClient != null) {
            registerMcpClientTools("brave-search", braveSearchMcpClient);
        }
        
        
        if (securityMcpClient != null) {
            registerMcpClientTools("security", securityMcpClient);
        }
        
        log.info("Spring AI 표준 MCP Function Callback 초기화 완료: {} 개 도구", toolCallbacks.size());
        logInitializationSummary();
    }
    
    
    private void logInitializationSummary() {
        Map<String, Long> clientCounts = toolClientMapping.values().stream()
            .collect(Collectors.groupingBy(client -> client, Collectors.counting()));
        
        log.info("MCP 도구 초기화 요약:");
        clientCounts.forEach((client, count) -> 
            log.info("  - {} 클라이언트: {} 개 도구", client, count)
        );
    }
    
    
    private void registerMcpClientTools(String clientName, McpSyncClient mcpClient) {
        try {
            log.info("{} MCP 클라이언트 도구 등록 시작", clientName);

            var toolsResult = mcpClient.listTools(null);
            if (toolsResult != null && toolsResult.tools() != null) {
                int registeredCount = 0;
                
                for (McpSchema.Tool tool : toolsResult.tools()) {
                    try {
                        
                        String toolName = tool.name();
                        
                        
                        if (toolCallbacks.containsKey(toolName)) {
                            log.debug("⏭️ 도구 이름 충돌 감지: {}. 기존 도구 유지, 새 도구 건너뜀", toolName);
                            continue; 
                        }
                        
                        
                        ToolCallback callback = new SyncMcpToolCallback(mcpClient, tool);
                        
                        
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
    
    
    
    private final Map<String, McpResource> mcpResources = new ConcurrentHashMap<>();
    
    
    public Map<String, McpResource> getMcpResources() {
        initializeMcpResources();
        return new HashMap<>(mcpResources);
    }
    
    
    private void initializeMcpResources() {
        if (!mcpResources.isEmpty()) {
            return; 
        }
        
        log.info("📚 MCP Resources 초기화 시작");
        
        
        if (securityMcpClient != null) {
            registerMcpClientResources("security", securityMcpClient);
        }
        
        log.info("MCP Resources 초기화 완료: {} 개", mcpResources.size());
    }
    
    
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

    

    private final Map<String, McpPrompt> mcpPrompts = new ConcurrentHashMap<>();

    
    public Map<String, McpPrompt> getMcpPrompts() {
        initializeMcpPrompts();
        return new HashMap<>(mcpPrompts);
    }

    
    private void initializeMcpPrompts() {
        if (!mcpPrompts.isEmpty()) {
            return; 
        }

        log.info("MCP Prompts 초기화 시작");

        
        if (securityMcpClient != null) {
            registerMcpClientPrompts("security", securityMcpClient);
        }

        log.info("MCP Prompts 초기화 완료: {} 개", mcpPrompts.size());
    }

    
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