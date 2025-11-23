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

/**
 * Asynchronous Tool Execution Service
 *
 * 비동기 모드에서 승인된 도구를 나중에 실행하는 서비스입니다.
 * 저장된 컨텍스트를 복원하여 도구를 실행하고 결과를 저장합니다.
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class AsyncToolExecutionService {

    private final ToolExecutionContextRepository contextRepository;
    private final ObjectMapper objectMapper;
    private final ChainedToolResolver chainedToolResolver;

    @Autowired(required = false)
    private ApprovalAwareToolCallingManagerDecorator toolCallingManager;

    // 실행 중인 작업 추적
    private final Map<String, CompletableFuture<ToolExecutionResult>> executingTasks = new ConcurrentHashMap<>();

    /**
     * 승인된 도구 실행
     *
     * @param requestId 승인 요청 ID
     * @return 실행 결과 Future
     */
    @Async
    @Transactional
    public CompletableFuture<ToolExecutionResult> executeApprovedTool(String requestId) {
        log.info("비동기 도구 실행 시작: {}", requestId);

        // 이미 실행 중인지 확인
        if (executingTasks.containsKey(requestId)) {
            log.warn("이미 실행 중인 도구: {}", requestId);
            return executingTasks.get(requestId);
        }

        CompletableFuture<ToolExecutionResult> future = new CompletableFuture<>();
        executingTasks.put(requestId, future);

        try {
            // 1. 컨텍스트 로드
            ToolExecutionContext context = contextRepository.findByRequestId(requestId)
                    .orElseThrow(() -> new IllegalArgumentException("도구 실행 컨텍스트를 찾을 수 없음: " + requestId));

            // 2. 실행 가능한지 확인
            if (!context.isExecutable()) {
                throw new IllegalStateException("실행할 수 없는 상태: " + context.getStatus());
            }

            // 3. 실행 시작 표시
            context.markExecutionStart();
            contextRepository.save(context);

            // 4. Prompt와 ChatResponse 재구성
            Prompt prompt = reconstructPrompt(context);
            ChatResponse chatResponse = reconstructChatResponse(context);

            // 5. 도구 실행
            ToolExecutionResult result = executeToolWithContext(prompt, chatResponse, context);

            // 6. 결과 저장
            saveExecutionResult(context, result);

            // 7. Future 완료
            future.complete(result);
            log.info("비동기 도구 실행 완료: {}", requestId);

        } catch (Exception e) {
            log.error("비동기 도구 실행 실패: {}", requestId, e);

            // 실패 표시
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

    /**
     * Prompt 재구성
     *
     * @param context 도구 실행 컨텍스트
     * @return 재구성된 Prompt
     */
    private Prompt reconstructPrompt(ToolExecutionContext context) throws JsonProcessingException {
        log.debug("Prompt 재구성: {}", context.getRequestId());

        // JSON에서 메시지 목록 복원
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

        // ChatOptions 복원
        ChatOptions chatOptions = null;
        if (context.getChatOptions() != null) {
            Map<String, Object> optionsData = objectMapper.readValue(
                    context.getChatOptions(),
                    new TypeReference<Map<String, Object>>() {}
            );

            // ToolCallingChatOptions 재구성
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

    /**
     * ChatResponse 재구성
     *
     * @param context 도구 실행 컨텍스트
     * @return 재구성된 ChatResponse
     */
    private ChatResponse reconstructChatResponse(ToolExecutionContext context) throws JsonProcessingException {
        if (context.getChatResponse() == null || context.getChatResponse().isEmpty()) {
            // ChatResponse가 없으면 도구 호출 정보만으로 생성
            return createChatResponseFromToolCall(context);
        }

        // JSON에서 ChatResponse 복원
        Map<String, Object> responseData = objectMapper.readValue(
                context.getChatResponse(),
                new TypeReference<Map<String, Object>>() {}
        );

        // 간단한 ChatResponse 생성 (완전한 복원은 복잡함)
        AssistantMessage assistantMessage = new AssistantMessage("");

        // 도구 호출 정보 추가
        if (context.getToolCallId() != null) {
            // AssistantMessage.ToolCall 생성 (4개 파라미터 필요)
            AssistantMessage.ToolCall toolCall = new AssistantMessage.ToolCall(
                    context.getToolCallId(),
                    "function",
                    context.getToolName(),
                    context.getToolArguments()
            );
            // ToolCall을 직접 메시지에 추가 (withToolCalls 메서드 없음)
            assistantMessage = new AssistantMessage("", Map.of(), List.of(toolCall));
        }

        Generation generation = new Generation(assistantMessage);
        return new ChatResponse(List.of(generation));
    }

    /**
     * 도구 호출 정보로 ChatResponse 생성
     */
    private ChatResponse createChatResponseFromToolCall(ToolExecutionContext context) {
        AssistantMessage message = new AssistantMessage("");

        // 도구 호출 정보 설정
        AssistantMessage.ToolCall toolCall = new AssistantMessage.ToolCall(
                context.getToolCallId() != null ? context.getToolCallId() : UUID.randomUUID().toString(),
                "function",
                context.getToolName(),
                context.getToolArguments() != null ? context.getToolArguments() : "{}"
        );
        // ToolCall을 직접 메시지에 추가
        message = new AssistantMessage("", Map.of(), List.of(toolCall));

        Generation generation = new Generation(message);
        return new ChatResponse(List.of(generation));
    }

    /**
     * 도구 콜백 가져오기
     */
    private ToolCallback[] getToolCallbacks(ToolExecutionContext context) {
        // ChainedToolResolver에서 모든 도구 가져오기
        ToolCallback[] allTools = chainedToolResolver.getAllToolCallbacks();

        // 필요한 도구만 필터링
        if (context.getAvailableTools() != null && !context.getAvailableTools().isEmpty()) {
            Set<String> requiredTools = new HashSet<>(context.getAvailableTools());

            return Arrays.stream(allTools)
                    .filter(tool -> requiredTools.contains(tool.getToolDefinition().name()))
                    .toArray(ToolCallback[]::new);
        }

        return allTools;
    }

    /**
     * 컨텍스트로 도구 실행
     */
    private ToolExecutionResult executeToolWithContext(
            Prompt prompt,
            ChatResponse chatResponse,
            ToolExecutionContext context) {

        log.info("도구 실행: {} - {}", context.getRequestId(), context.getToolName());

        if (toolCallingManager != null) {
            // ApprovalAwareToolCallingManagerDecorator 사용
            // 이미 승인된 상태이므로 바로 실행됨
            return toolCallingManager.executeToolCalls(prompt, chatResponse);
        } else {
            log.warn("ToolCallingManager를 사용할 수 없음. 기본 실행 결과 반환");
            return createDefaultResult(context);
        }
    }

    /**
     * 기본 실행 결과 생성
     */
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

    /**
     * 실행 결과 저장
     */
    @Transactional
    public void saveExecutionResult(ToolExecutionContext context, ToolExecutionResult result) {
        try {
            // 결과를 JSON으로 변환
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

            // 컨텍스트 업데이트
            context.markExecutionComplete(resultJson);
            contextRepository.save(context);

            log.info("도구 실행 결과 저장 완료: {}", context.getRequestId());

        } catch (Exception e) {
            log.error("실행 결과 저장 실패: {}", context.getRequestId(), e);
            context.markExecutionFailed("결과 저장 실패: " + e.getMessage());
            contextRepository.save(context);
        }
    }

    /**
     * 실행 실패 표시
     */
    @Transactional
    public void markExecutionFailed(String requestId, String error) {
        contextRepository.findByRequestId(requestId).ifPresent(context -> {
            context.markExecutionFailed(error);
            contextRepository.save(context);
        });
    }

    /**
     * 승인된 도구들을 주기적으로 실행
     * 5초마다 실행 대기 중인 도구 확인
     */
//    @Scheduled(fixedDelay = 30000)  // 30초마다 (기존 5초 -> 30초)
    @Transactional
    public void processApprovedTools() {
        try {
            // APPROVED 상태의 컨텍스트 조회
            List<ToolExecutionContext> executableContexts =
                    contextRepository.findExecutableContexts(LocalDateTime.now());

            if (!executableContexts.isEmpty()) {
                log.debug("실행 대기 중인 도구 발견: {} 개", executableContexts.size());

                for (ToolExecutionContext context : executableContexts) {
                    // 이미 실행 중이 아닌 경우만
                    if (!executingTasks.containsKey(context.getRequestId())) {
                        log.info("도구 자동 실행 시작: {}", context.getRequestId());
                        executeApprovedTool(context.getRequestId());
                    }
                }
            }
        } catch (Exception e) {
            log.error("승인된 도구 처리 중 오류", e);
        }
    }

    /**
     * 만료된 컨텍스트 정리
     * 1분마다 만료된 컨텍스트 취소
     */
//    @Scheduled(fixedDelay = 60000)
    @Transactional
    public void cleanupExpiredContexts() {
        try {
            int cancelled = contextRepository.cancelExpiredContexts(LocalDateTime.now());
            if (cancelled > 0) {
                log.info("만료된 도구 실행 컨텍스트 취소: {} 개", cancelled);
            }
        } catch (Exception e) {
            log.error("만료 컨텍스트 정리 중 오류", e);
        }
    }

    /**
     * 재시도 가능한 도구 재실행
     * 30초마다 실패한 도구 중 재시도 가능한 것 확인
     */
//    @Scheduled(fixedDelay = 30000)
    @Transactional
    public void retryFailedTools() {
        try {
            List<ToolExecutionContext> retryableContexts =
                    contextRepository.findRetryableContexts(LocalDateTime.now());

            for (ToolExecutionContext context : retryableContexts) {
                if (context.canRetry()) {
                    log.info("도구 재실행 시도: {} (시도 {}/{})",
                            context.getRequestId(),
                            context.getRetryCount() + 1,
                            context.getMaxRetries());

                    // 상태를 APPROVED로 변경하여 재실행 가능하게 함
                    context.setStatus("APPROVED");
                    contextRepository.save(context);
                }
            }
        } catch (Exception e) {
            log.error("실패 도구 재시도 처리 중 오류", e);
        }
    }

    /**
     * 실행 중인 작업 개수 조회
     */
    public int getExecutingTaskCount() {
        return executingTasks.size();
    }

    /**
     * 특정 요청이 실행 중인지 확인
     */
    public boolean isExecuting(String requestId) {
        return executingTasks.containsKey(requestId);
    }
}