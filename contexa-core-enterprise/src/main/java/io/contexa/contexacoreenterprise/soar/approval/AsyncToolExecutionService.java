package io.contexa.contexacoreenterprise.soar.approval;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolExecutionResult;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class AsyncToolExecutionService {

    private final ToolExecutionContextRepository contextRepository;
    private final ObjectMapper objectMapper;
    private final ChainedToolResolver chainedToolResolver;

    @Autowired(required = false)
    @Qualifier("defaultToolCallingManager")
    private DefaultToolCallingManager toolCallingManager;

    private final Map<String, CompletableFuture<ToolExecutionResult>> executingTasks = new ConcurrentHashMap<>();

    @Async
    @Transactional
    public CompletableFuture<ToolExecutionResult> executeApprovedTool(String requestId) {

        CompletableFuture<ToolExecutionResult> future = new CompletableFuture<>();
        CompletableFuture<ToolExecutionResult> existing = executingTasks.putIfAbsent(requestId, future);
        if (existing != null) {
            log.error("Tool already executing: {}", requestId);
            return existing;
        }

        try {
            
            ToolExecutionContext context = contextRepository.findByRequestId(requestId)
                    .orElseThrow(() -> new IllegalArgumentException("Tool execution context not found: " + requestId));

            if (!context.isExecutable()) {
                throw new IllegalStateException("Not in executable state: " + context.getStatus());
            }

            context.markExecutionStart();
            contextRepository.save(context);

            Prompt prompt = reconstructPrompt(context);
            ChatResponse chatResponse = reconstructChatResponse(context);

            ToolExecutionResult result = executeToolWithContext(prompt, chatResponse, context);

            saveExecutionResult(context, result);

            future.complete(result);
            
        } catch (Exception e) {
            log.error("Async tool execution failed: {}", requestId, e);

            try {
                markExecutionFailed(requestId, e.getMessage());
            } catch (Exception ex) {
                log.error("Error marking execution as failed: {}", requestId, ex);
            }

            future.completeExceptionally(e);
        } finally {
            executingTasks.remove(requestId);
        }

        return future;
    }

    private Prompt reconstructPrompt(ToolExecutionContext context) throws JsonProcessingException {

        List<Map<String, String>> messageData = objectMapper.readValue(
                context.getPromptContent(),
                new TypeReference<List<Map<String, String>>>() {}
        );

        List<Message> messages = new ArrayList<>();
        for (Map<String, String> msg : messageData) {
            String role = msg.get("role");
            String content = msg.get("content");

            Message message = switch (role.toLowerCase()) {
                case "system" -> new SystemMessage(content);
                case "user" -> new UserMessage(content);
                case "assistant" -> new AssistantMessage(content);
                default -> new UserMessage(content);
            };

            messages.add(message);
        }

        ChatOptions chatOptions = null;
        if (context.getChatOptions() != null) {
            Map<String, Object> optionsData = objectMapper.readValue(
                    context.getChatOptions(),
                    new TypeReference<Map<String, Object>>() {}
            );

            ToolCallback[] toolCallbacks = getToolCallbacks(context);

            @SuppressWarnings("unchecked")
            Set<String> toolNames = new HashSet<>((List<String>) optionsData.getOrDefault("toolNames", new ArrayList<>()));

            chatOptions = ToolCallingChatOptions.builder()
                    .toolCallbacks(toolCallbacks)
                    .toolNames(toolNames)
                    .internalToolExecutionEnabled(false)
                    .build();
        }

        return new Prompt(messages, chatOptions != null ? chatOptions : ChatOptions.builder().build());
    }

    private ChatResponse reconstructChatResponse(ToolExecutionContext context) throws JsonProcessingException {
        if (context.getChatResponse() == null || context.getChatResponse().isEmpty()) {
            return createChatResponseFromToolCall(context);
        }

        String chatResponseJson = context.getChatResponse().trim();
        List<AssistantMessage.ToolCall> toolCalls = new ArrayList<>();

        if (chatResponseJson.startsWith("[")) {
            List<Map<String, Object>> toolCallsData = objectMapper.readValue(
                    chatResponseJson,
                    new TypeReference<List<Map<String, Object>>>() {}
            );
            for (Map<String, Object> toolData : toolCallsData) {
                toolCalls.add(new AssistantMessage.ToolCall(
                        (String) toolData.get("toolCallId"),
                        "function",
                        (String) toolData.get("toolName"),
                        (String) toolData.get("arguments")
                ));
            }
        } else if (context.getToolCallId() != null) {
            toolCalls.add(new AssistantMessage.ToolCall(
                    context.getToolCallId(),
                    "function",
                    context.getToolName(),
                    context.getToolArguments()
            ));
        }

        AssistantMessage assistantMessage = toolCalls.isEmpty()
                ? new AssistantMessage("")
                : new AssistantMessage("", Map.of(), toolCalls);

        Generation generation = new Generation(assistantMessage);
        return new ChatResponse(List.of(generation));
    }

    private ChatResponse createChatResponseFromToolCall(ToolExecutionContext context) {
        AssistantMessage message = new AssistantMessage("");

        AssistantMessage.ToolCall toolCall = new AssistantMessage.ToolCall(
                context.getToolCallId() != null ? context.getToolCallId() : UUID.randomUUID().toString(),
                "function",
                context.getToolName(),
                context.getToolArguments() != null ? context.getToolArguments() : "{}"
        );
        
        message = new AssistantMessage("", Map.of(), List.of(toolCall));

        Generation generation = new Generation(message);
        return new ChatResponse(List.of(generation));
    }

    private ToolCallback[] getToolCallbacks(ToolExecutionContext context) {
        
        ToolCallback[] allTools = chainedToolResolver.getAllToolCallbacks();

        if (context.getAvailableTools() != null && !context.getAvailableTools().isEmpty()) {
            Set<String> requiredTools = new HashSet<>(context.getAvailableTools());

            return Arrays.stream(allTools)
                    .filter(tool -> requiredTools.contains(tool.getToolDefinition().name()))
                    .toArray(ToolCallback[]::new);
        }

        return allTools;
    }

    private ToolExecutionResult executeToolWithContext(
            Prompt prompt,
            ChatResponse chatResponse,
            ToolExecutionContext context) {

        if (toolCallingManager != null) {

            return toolCallingManager.executeToolCalls(prompt, chatResponse);
        } else {
            log.error("ToolCallingManager unavailable. Returning default execution result");
            return createDefaultResult(context);
        }
    }

    private ToolExecutionResult createDefaultResult(ToolExecutionContext context) {
        List<Message> history = new ArrayList<>();
        history.add(new AssistantMessage(
                String.format("Tool %s executed in async mode (request ID: %s)",
                        context.getToolName(), context.getRequestId())
        ));

        return ToolExecutionResult.builder()
                .conversationHistory(history)
                .returnDirect(true)
                .build();
    }

    @Transactional
    public void saveExecutionResult(ToolExecutionContext context, ToolExecutionResult result) {
        try {
            
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("success", true);
            resultData.put("timestamp", LocalDateTime.now());

            result.conversationHistory();
            List<Map<String, String>> messages = result.conversationHistory().stream()
                    .map(msg -> {
                        Map<String, String> msgData = new HashMap<>();
                        msgData.put("type", msg.getClass().getSimpleName());
                        msgData.put("content", msg.getText());
                        return msgData;
                    })
                    .collect(Collectors.toList());
            resultData.put("messages", messages);

            resultData.put("returnDirect", result.returnDirect());

            String resultJson = objectMapper.writeValueAsString(resultData);

            context.markExecutionComplete(resultJson);
            contextRepository.save(context);

        } catch (Exception e) {
            log.error("Failed to save execution result: {}", context.getRequestId(), e);
            context.markExecutionFailed("Result save failed: " + e.getMessage());
            contextRepository.save(context);
        }
    }

    @Transactional
    public void markExecutionFailed(String requestId, String error) {
        contextRepository.findByRequestId(requestId).ifPresent(context -> {
            context.markExecutionFailed(error);
            contextRepository.save(context);
        });
    }

    @Scheduled(fixedDelay = 30000)
    @Transactional
    public void processApprovedTools() {
        try {
            
            List<ToolExecutionContext> executableContexts =
                    contextRepository.findExecutableContexts(LocalDateTime.now());

            if (!executableContexts.isEmpty()) {
                
                for (ToolExecutionContext context : executableContexts) {
                    
                    if (!executingTasks.containsKey(context.getRequestId())) {
                                                executeApprovedTool(context.getRequestId());
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error processing approved tools", e);
        }
    }

    @Scheduled(fixedDelay = 60000)
    @Transactional
    public void cleanupExpiredContexts() {
        try {
            int cancelled = contextRepository.cancelExpiredContexts(LocalDateTime.now());
            if (cancelled > 0) {
                log.error("Cleanup expired contexts: cancelled {} entries", cancelled);
            }
        } catch (Exception e) {
            log.error("Error cleaning up expired contexts", e);
        }
    }

}