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
import org.springframework.beans.factory.annotation.Autowired;
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
    private ApprovalAwareToolCallingManagerDecorator toolCallingManager;

    private final Map<String, CompletableFuture<ToolExecutionResult>> executingTasks = new ConcurrentHashMap<>();

    @Async
    @Transactional
    public CompletableFuture<ToolExecutionResult> executeApprovedTool(String requestId) {

        if (executingTasks.containsKey(requestId)) {
            log.warn("이미 실행 중인 도구: {}", requestId);
            return executingTasks.get(requestId);
        }

        CompletableFuture<ToolExecutionResult> future = new CompletableFuture<>();
        executingTasks.put(requestId, future);

        try {
            
            ToolExecutionContext context = contextRepository.findByRequestId(requestId)
                    .orElseThrow(() -> new IllegalArgumentException("도구 실행 컨텍스트를 찾을 수 없음: " + requestId));

            if (!context.isExecutable()) {
                throw new IllegalStateException("실행할 수 없는 상태: " + context.getStatus());
            }

            context.markExecutionStart();
            contextRepository.save(context);

            Prompt prompt = reconstructPrompt(context);
            ChatResponse chatResponse = reconstructChatResponse(context);

            ToolExecutionResult result = executeToolWithContext(prompt, chatResponse, context);

            saveExecutionResult(context, result);

            future.complete(result);
            
        } catch (Exception e) {
            log.error("비동기 도구 실행 실패: {}", requestId, e);

            try {
                markExecutionFailed(requestId, e.getMessage());
            } catch (Exception ex) {
                log.error("실행 실패 표시 중 오류: {}", requestId, ex);
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

        Map<String, Object> responseData = objectMapper.readValue(
                context.getChatResponse(),
                new TypeReference<Map<String, Object>>() {}
        );

        AssistantMessage assistantMessage = new AssistantMessage("");

        if (context.getToolCallId() != null) {
            
            AssistantMessage.ToolCall toolCall = new AssistantMessage.ToolCall(
                    context.getToolCallId(),
                    "function",
                    context.getToolName(),
                    context.getToolArguments()
            );
            
            assistantMessage = new AssistantMessage("", Map.of(), List.of(toolCall));
        }

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
            log.warn("ToolCallingManager를 사용할 수 없음. 기본 실행 결과 반환");
            return createDefaultResult(context);
        }
    }

    private ToolExecutionResult createDefaultResult(ToolExecutionContext context) {
        List<Message> history = new ArrayList<>();
        history.add(new AssistantMessage(
                String.format("도구 %s이(가) 비동기 모드에서 실행되었습니다 (요청 ID: %s)",
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

            if (result.conversationHistory() != null) {
                List<Map<String, String>> messages = result.conversationHistory().stream()
                        .map(msg -> {
                            Map<String, String> msgData = new HashMap<>();
                            msgData.put("type", msg.getClass().getSimpleName());
                            msgData.put("content", msg.getText());
                            return msgData;
                        })
                        .collect(Collectors.toList());
                resultData.put("messages", messages);
            }

            resultData.put("returnDirect", result.returnDirect());

            String resultJson = objectMapper.writeValueAsString(resultData);

            context.markExecutionComplete(resultJson);
            contextRepository.save(context);

        } catch (Exception e) {
            log.error("실행 결과 저장 실패: {}", context.getRequestId(), e);
            context.markExecutionFailed("결과 저장 실패: " + e.getMessage());
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
            log.error("승인된 도구 처리 중 오류", e);
        }
    }

    @Transactional
    public void cleanupExpiredContexts() {
        try {
            int cancelled = contextRepository.cancelExpiredContexts(LocalDateTime.now());
            if (cancelled > 0) {
                            }
        } catch (Exception e) {
            log.error("만료 컨텍스트 정리 중 오류", e);
        }
    }

    @Transactional
    public void retryFailedTools() {
        try {
            List<ToolExecutionContext> retryableContexts =
                    contextRepository.findRetryableContexts(LocalDateTime.now());

            for (ToolExecutionContext context : retryableContexts) {
                if (context.canRetry()) {

                    context.setStatus("APPROVED");
                    contextRepository.save(context);
                }
            }
        } catch (Exception e) {
            log.error("실패 도구 재시도 처리 중 오류", e);
        }
    }

    public int getExecutingTaskCount() {
        return executingTasks.size();
    }

    public boolean isExecuting(String requestId) {
        return executingTasks.containsKey(requestId);
    }
}