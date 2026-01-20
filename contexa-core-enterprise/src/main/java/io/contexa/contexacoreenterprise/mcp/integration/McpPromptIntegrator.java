package io.contexa.contexacoreenterprise.mcp.integration;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class McpPromptIntegrator {
    
    private final McpSyncClient braveSearchMcpClient;
    private final McpSyncClient securityMcpClient;
    private final Map<String, PromptTemplate> promptTemplates = new ConcurrentHashMap<>();
    
    
    public Optional<Prompt> getPrompt(String promptName, Map<String, Object> arguments) {
        initializePrompts();
        
        PromptTemplate template = promptTemplates.get(promptName);
        if (template == null) {
            log.warn("프롬프트 템플릿을 찾을 수 없음: {}", promptName);
            return Optional.empty();
        }
        
        try {
            List<Message> messages = template.generateMessages(arguments);
            return Optional.of(new Prompt(messages));
        } catch (Exception e) {
            log.error("프롬프트 생성 실패: {} - {}", promptName, e.getMessage());
            return Optional.empty();
        }
    }
    
    
    public Optional<String> getSystemPrompt(String promptName, Map<String, Object> arguments) {
        initializePrompts();
        
        PromptTemplate template = promptTemplates.get(promptName);
        if (template == null) {
            return Optional.empty();
        }
        
        try {
            return Optional.of(template.generateSystemPrompt(arguments));
        } catch (Exception e) {
            log.error("시스템 프롬프트 생성 실패: {} - {}", promptName, e.getMessage());
            return Optional.empty();
        }
    }
    
    
    public Optional<String> getUserPrompt(String promptName, Map<String, Object> arguments) {
        initializePrompts();
        
        PromptTemplate template = promptTemplates.get(promptName);
        if (template == null) {
            return Optional.empty();
        }
        
        try {
            return Optional.of(template.generateUserPrompt(arguments));
        } catch (Exception e) {
            log.error("사용자 프롬프트 생성 실패: {} - {}", promptName, e.getMessage());
            return Optional.empty();
        }
    }
    
    
    public List<PromptInfo> listAvailablePrompts() {
        initializePrompts();
        
        return promptTemplates.values().stream()
            .map(template -> new PromptInfo(
                template.getName(),
                template.getDescription(),
                template.getArguments(),
                template.getClientName()
            ))
            .collect(Collectors.toList());
    }
    
    
    public List<PromptInfo> findPromptsByDomain(String domain) {
        initializePrompts();
        
        return promptTemplates.values().stream()
            .filter(template -> template.matchesDomain(domain))
            .map(template -> new PromptInfo(
                template.getName(),
                template.getDescription(),
                template.getArguments(),
                template.getClientName()
            ))
            .collect(Collectors.toList());
    }
    
    
    private void initializePrompts() {
        if (!promptTemplates.isEmpty()) {
            return; 
        }
        
        log.info("MCP Prompt Integrator 초기화 시작");
        
        
        if (braveSearchMcpClient != null) {
            registerClientPrompts("brave-search", braveSearchMcpClient);
        }
        
        
        if (securityMcpClient != null) {
            registerClientPrompts("security", securityMcpClient);
        }
        
        log.info("MCP Prompt Integrator 초기화 완료: {} 개 프롬프트", promptTemplates.size());
    }
    
    
    private void registerClientPrompts(String clientName, McpSyncClient mcpClient) {
        try {
            log.info("💭 {} MCP 클라이언트 프롬프트 등록 시작", clientName);
            
            var listResult = mcpClient.listPrompts(null);
            if (listResult != null && listResult.prompts() != null) {
                for (var prompt : listResult.prompts()) {
                    String fullName = String.format("%s_%s", clientName, prompt.name());
                    PromptTemplate template = new PromptTemplate(
                        fullName,
                        prompt,
                        mcpClient,
                        clientName
                    );
                    promptTemplates.put(fullName, template);
                    
                    log.debug("프롬프트 템플릿 등록: {} - {}", fullName, prompt.description());
                }
                
                log.info("{} MCP 클라이언트 프롬프트 등록 완료: {} 개",
                        clientName, listResult.prompts().size());
            }
        } catch (Exception e) {
            log.warn("{} MCP 클라이언트 프롬프트 등록 실패: {}", clientName, e.getMessage());
        }
    }
    
    
    public record PromptInfo(
        String name,
        String description,
        List<String> arguments,
        String clientName
    ) {}
    
    
    private static class PromptTemplate {
        private final String name;
        private final McpSchema.Prompt prompt;
        private final McpSyncClient client;
        private final String clientName;
        
        public PromptTemplate(String name, McpSchema.Prompt prompt, 
                             McpSyncClient client, String clientName) {
            this.name = name;
            this.prompt = prompt;
            this.client = client;
            this.clientName = clientName;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return prompt.description() != null ? 
                prompt.description() : "MCP Prompt: " + name;
        }
        
        public List<String> getArguments() {
            if (prompt.arguments() == null) {
                return List.of();
            }
            
            List<String> args = new ArrayList<>();
            for (var arg : prompt.arguments()) {
                if (arg.name() != null) {
                    String argDesc = arg.name();
                    if (arg.required() != null && arg.required()) {
                        argDesc += " (required)";
                    }
                    if (arg.description() != null) {
                        argDesc += ": " + arg.description();
                    }
                    args.add(argDesc);
                }
            }
            return args;
        }
        
        public String getClientName() {
            return clientName;
        }
        
        
        public List<Message> generateMessages(Map<String, Object> arguments) {
            try {
                log.debug("MCP Prompt 메시지 생성: {} - 인수: {}", name, arguments);
                
                var getResult = client.getPrompt(
                    new McpSchema.GetPromptRequest(prompt.name(), arguments != null ? arguments : Map.of())
                );
                
                if (getResult != null && getResult.messages() != null) {
                    List<Message> messages = new ArrayList<>();
                    
                    for (var mcpMessage : getResult.messages()) {
                        String content = extractContent(mcpMessage.content());
                        
                        if (mcpMessage.role() != null && content != null) {
                            String roleStr = mcpMessage.role().toString().toLowerCase();
                            Message message = switch (roleStr) {
                                case "system" -> new SystemMessage(content);
                                case "user" -> new UserMessage(content);
                                case "assistant" -> new AssistantMessage(content);
                                default -> new UserMessage(content); 
                            };
                            messages.add(message);
                        }
                    }
                    
                    return messages;
                }
                
                return List.of();
                
            } catch (Exception e) {
                log.error("MCP Prompt 메시지 생성 실패: {} - {}", name, e.getMessage());
                throw new RuntimeException("프롬프트 메시지 생성 실패: " + e.getMessage(), e);
            }
        }
        
        
        public String generateSystemPrompt(Map<String, Object> arguments) {
            List<Message> messages = generateMessages(arguments);
            
            StringBuilder sb = new StringBuilder();
            for (Message msg : messages) {
                if (msg instanceof SystemMessage systemMsg) {
                    if (sb.length() > 0) sb.append("\n\n");
                    
                    sb.append(systemMsg.getText());
                }
            }
            return sb.toString();
        }
        
        
        public String generateUserPrompt(Map<String, Object> arguments) {
            List<Message> messages = generateMessages(arguments);
            
            StringBuilder sb = new StringBuilder();
            for (Message msg : messages) {
                if (msg instanceof UserMessage userMsg) {
                    if (sb.length() > 0) sb.append("\n\n");
                    
                    sb.append(userMsg.getText());
                }
            }
            return sb.toString();
        }
        
        
        private String extractContent(Object content) {
            if (content == null) {
                return null;
            }
            
            if (content instanceof McpSchema.TextContent textContent) {
                return textContent.text();
            } else if (content instanceof McpSchema.ImageContent imageContent) {
                
                return "[Image: " + imageContent.data() + "]";
            } else if (content instanceof String) {
                return (String) content;
            }
            
            return content.toString();
        }
        
        
        public boolean matchesDomain(String domain) {
            if (domain == null || domain.isEmpty()) {
                return true;
            }
            
            String lowerDomain = domain.toLowerCase();
            String lowerName = name.toLowerCase();
            String lowerDesc = getDescription().toLowerCase();
            
            return lowerName.contains(lowerDomain) || 
                   lowerDesc.contains(lowerDomain);
        }
    }
    
    
    public Map<String, Object> getPromptStatistics() {
        initializePrompts();
        
        Map<String, Integer> clientCounts = new HashMap<>();
        Map<String, List<String>> promptsByClient = new HashMap<>();
        
        for (PromptTemplate template : promptTemplates.values()) {
            String client = template.getClientName();
            clientCounts.merge(client, 1, Integer::sum);
            promptsByClient.computeIfAbsent(client, k -> new ArrayList<>())
                          .add(template.getName());
        }
        
        return Map.of(
            "total", promptTemplates.size(),
            "byClient", clientCounts,
            "prompts", promptsByClient
        );
    }
    
    
    public Optional<Prompt> enhancePromptWithMcp(
            String baseSystemPrompt,
            String baseUserPrompt,
            String mcpPromptName,
            Map<String, Object> arguments) {
        
        
        Optional<Prompt> mcpPromptOpt = getPrompt(mcpPromptName, arguments);
        
        if (mcpPromptOpt.isEmpty()) {
            
            return Optional.of(new Prompt(List.of(
                new SystemMessage(baseSystemPrompt),
                new UserMessage(baseUserPrompt)
            )));
        }
        
        
        Prompt mcpPrompt = mcpPromptOpt.get();
        List<Message> combinedMessages = new ArrayList<>();
        
        
        String systemContent = baseSystemPrompt;
        for (Message msg : mcpPrompt.getInstructions()) {
            if (msg instanceof SystemMessage) {
                systemContent += "\n\n" + ((SystemMessage) msg).getText();
            }
        }
        combinedMessages.add(new SystemMessage(systemContent));
        
        
        combinedMessages.add(new UserMessage(baseUserPrompt));
        
        
        for (Message msg : mcpPrompt.getInstructions()) {
            if (!(msg instanceof SystemMessage)) {
                combinedMessages.add(msg);
            }
        }
        
        return Optional.of(new Prompt(combinedMessages));
    }
}