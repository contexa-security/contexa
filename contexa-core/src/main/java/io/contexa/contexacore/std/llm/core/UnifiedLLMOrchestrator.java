package io.contexa.contexacore.std.llm.core;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaOptions;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * 통합 LLM 오케스트레이터
 * 
 * LLMClient와 ToolCapableLLMClient를 직접 구현하여
 * 기존 코드와 100% 호환성 제공하면서 새로운 아키텍처 적용
 * 
 * SOLID 원칙:
 * - SRP: 모델 선택, ChatClient 생성, 도구 실행 등을 별도 컴포넌트로 분리
 * - OCP: Strategy 패턴으로 새로운 모델 선택 전략 추가 가능
 * - DIP: 추상화에 의존 (ModelSelectionStrategy, ChatClientFactory 등)
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedLLMOrchestrator implements LLMOperations, ToolCapableLLMClient {

    private final ModelSelectionStrategy modelSelectionStrategy;
    private final StreamingHandler streamingHandler;
    private final TieredLLMProperties tieredLLMProperties;
    
    // =====================================
    // LLMOperations 구현 (새로운 인터페이스)
    // =====================================
    
    @Override
    public Mono<String> execute(ExecutionContext context) {
        // AI Native v4.2.0: null 체크 강화
        if (context == null) {
            return Mono.error(new IllegalArgumentException("ExecutionContext cannot be null"));
        }
        if (context.getPrompt() == null) {
            return Mono.error(new IllegalArgumentException("Prompt cannot be null"));
        }

        log.debug("LLM 실행 시작 - RequestId: {}, TaskType: {}, SecurityTaskType: {}",
                context.getRequestId(), context.getTaskType(), context.getSecurityTaskType());

        return Mono.fromCallable(() -> {
            // 1. 모델 선택
            ChatModel selectedModel = modelSelectionStrategy.selectModel(context);
            log.info("선택된 모델: {}", selectedModel.getClass().getSimpleName());
            
            // 2. ChatClient 생성 (직접 구현)
            ChatClient chatClient = ChatClient.builder(selectedModel).build();
            
            // 3. 프롬프트 실행 시작 - 올바른 Spring AI API 사용
            var promptSpec = chatClient.prompt(context.getPrompt());
            
            // 4. 옵션 적용 (모델명 포함)
            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            } else if (context.getTemperature() != null || context.getMaxTokens() != null ||
                      context.getPreferredModel() != null || context.getTier() != null ||
                      context.getAnalysisLevel() != null) {
                // OllamaChatModel인 경우 tier 기반 모델 선택 로직 적용
                if (selectedModel instanceof OllamaChatModel) {
                    String modelName = determineOllamaModelName(context);
                    if (modelName != null) {
                        OllamaOptions ollamaOptions = OllamaOptions.builder()
                            .model(modelName)
                            .temperature(context.getTemperature() != null ? context.getTemperature() : 0.7d)
                            .build();
                        promptSpec = promptSpec.options(ollamaOptions);
                        log.info("Ollama 모델 설정: {}, Temperature: {}", modelName,
                                context.getTemperature() != null ? context.getTemperature() : 0.7d);
                    }
                } else {
                    ChatOptions options = ChatOptions.builder()
                        .temperature(context.getTemperature())
                        .maxTokens(context.getMaxTokens())
                        .build();
                    promptSpec = promptSpec.options(options);
                }
            }
            
            // 5. 도구 실행 처리 (기존 시스템 활용 - ApprovalAwareToolCallingManagerDecorator 사용)
            if (context.getToolExecutionEnabled() != null && context.getToolExecutionEnabled()) {
                // 도구가 있으면 ToolCallback 으로 실행
                if (context.getToolCallbacks() != null && !context.getToolCallbacks().isEmpty()) {
                    promptSpec = promptSpec.toolCallbacks(context.getToolCallbacks());
                } else if (context.getToolProviders() != null && !context.getToolProviders().isEmpty()) {
                    promptSpec = promptSpec.tools(context.getToolProviders().toArray());
                }
            }
            
            // 6. 응답 반환 및 성능 메트릭 기록
            long startTime = System.currentTimeMillis();
            String response = promptSpec.call().content();
            long executionTime = System.currentTimeMillis() - startTime;

            String modelName = selectedModel.getClass().getSimpleName();
            modelSelectionStrategy.recordModelPerformance(modelName, executionTime, response != null);

            log.debug("LLM 실행 완료 - RequestId: {}, 모델: {}, 실행시간: {}ms, 응답 길이: {}",
                    context.getRequestId(), modelName, executionTime, response != null ? response.length() : 0);

            // AI Native v4.2.0: null 응답 처리 - 빈 문자열 대신 명시적 마커 반환
            if (response == null || response.isBlank()) {
                log.warn("LLM 응답이 null 또는 빈 문자열 - RequestId: {}", context.getRequestId());
                return "{}";  // 빈 JSON 반환 (파싱 가능)
            }

            return response;
        })
        // AI Native v4.2.0: 재시도 로직 추가 (일시적 오류 복구)
        .retryWhen(reactor.util.retry.Retry.backoff(2, java.time.Duration.ofSeconds(1))
            .filter(throwable -> throwable instanceof java.net.SocketTimeoutException
                || throwable instanceof java.io.IOException)
            .doBeforeRetry(retrySignal -> log.warn("LLM 재시도 #{} - RequestId: {}, 오류: {}",
                retrySignal.totalRetries() + 1, context.getRequestId(), retrySignal.failure().getMessage())))
        .doOnError(error -> log.error("LLM 실행 실패 - RequestId: {}", context.getRequestId(), error));
    }
    
    @Override
    public Flux<String> stream(ExecutionContext context) {
        log.debug("LLM 스트리밍 시작 - RequestId: {}", context.getRequestId());
        
        return Flux.defer(() -> {
            try {
                // 1. 모델 선택
                ChatModel selectedModel = modelSelectionStrategy.selectModel(context);
                
                // 2. ChatClient 생성 (직접 구현)
                ChatClient chatClient = ChatClient.builder(selectedModel).build();

                // 3. 스트리밍 처리 및 성능 메트릭 기록
                long startTime = System.currentTimeMillis();
                return streamingHandler.handleStreaming(chatClient, context)
                    .doOnComplete(() -> {
                        long executionTime = System.currentTimeMillis() - startTime;
                        String modelName = selectedModel.getClass().getSimpleName();
                        modelSelectionStrategy.recordModelPerformance(modelName, executionTime, true);
                        log.debug("스트리밍 완료 - 모델: {}, 실행시간: {}ms", modelName, executionTime);
                    })
                    .doOnError(error -> {
                        long executionTime = System.currentTimeMillis() - startTime;
                        String modelName = selectedModel.getClass().getSimpleName();
                        modelSelectionStrategy.recordModelPerformance(modelName, executionTime, false);
                        log.error("스트리밍 실패 - 모델: {}, 실행시간: {}ms", modelName, executionTime);
                    });
            } catch (Exception e) {
                log.error("LLM 스트리밍 실패 - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }
    
    @Override
    public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {
        // AI Native v4.2.0: null 체크 강화
        if (context == null || context.getPrompt() == null) {
            return Mono.error(new IllegalArgumentException("ExecutionContext and Prompt cannot be null"));
        }
        if (targetType == null) {
            return Mono.error(new IllegalArgumentException("Target type cannot be null"));
        }

        log.debug("LLM Entity 실행 - RequestId: {}, TargetType: {}",
                context.getRequestId(), targetType.getSimpleName());

        return Mono.fromCallable(() -> {
            // 1. 모델 선택
            ChatModel selectedModel = modelSelectionStrategy.selectModel(context);

            // 2. ChatClient 생성 (직접 구현)
            ChatClient chatClient = ChatClient.builder(selectedModel).build();

            // 3. Entity 변환 실행 - 올바른 Spring AI API 사용
            var promptSpec = chatClient.prompt(context.getPrompt());
            
            // 4. 옵션 적용
            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            }

            // 5. Entity로 응답 받기 및 성능 메트릭 기록
            long startTime = System.currentTimeMillis();
            T result = (T) promptSpec.call().entity(targetType);
            long executionTime = System.currentTimeMillis() - startTime;

            String modelName = selectedModel.getClass().getSimpleName();
            modelSelectionStrategy.recordModelPerformance(modelName, executionTime, result != null);

            log.debug("Entity 실행 완료 - 모델: {}, 실행시간: {}ms", modelName, executionTime);

            return result;
        })
        .doOnError(error -> log.error("LLM Entity 실행 실패 - RequestId: {}", context.getRequestId(), error));
    }
    
    /**
     * Ollama 모델명 결정 메서드
     * 우선순위: preferredModel > analysisLevel > tier
     * 설정 파일 기반으로 하드코딩 제거
     *
     * @param context ExecutionContext
     * @return 결정된 Ollama 모델명
     */
    private String determineOllamaModelName(ExecutionContext context) {
        // 1. 명시적으로 지정된 모델이 있으면 사용
        if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
            log.debug("지정된 모델 사용: {}", context.getPreferredModel());
            return context.getPreferredModel();
        }

        // 2. AnalysisLevel이 설정되어 있으면 해당 tier의 모델 사용
        if (context.getAnalysisLevel() != null) {
            int tier = context.getAnalysisLevel().getDefaultTier();
            String modelName = tieredLLMProperties.getModelNameForTier(tier);
            log.debug("AnalysisLevel {} -> Tier {} -> 모델: {}",
                     context.getAnalysisLevel(), tier, modelName);
            return modelName;
        }

        // 3. Tier가 직접 설정되어 있으면 해당 모델 사용
        if (context.getTier() != null) {
            String modelName = tieredLLMProperties.getModelNameForTier(context.getTier());
            log.debug("Tier {} -> 모델: {}", context.getTier(), modelName);
            return modelName;
        }

        // 4. SecurityTaskType 기반 선택 (설정 파일 기반)
        if (context.getSecurityTaskType() != null) {
            int tier = context.getSecurityTaskType().getDefaultTier();
            String modelName = tieredLLMProperties.getModelNameForTier(tier);
            log.debug("SecurityTaskType {} -> Tier {} -> 모델: {}",
                     context.getSecurityTaskType(), tier, modelName);
            return modelName;
        }

        // 5. 기본값 (설정 파일에서 읽음)
        String defaultModel = tieredLLMProperties.getModelNameForTier(1);  // Layer 1을 기본으로
        log.warn("모델 선택 불가능, 기본 모델 사용: {}", defaultModel);
        return defaultModel;
    }


    // =====================================
    // LLMClient 구현 (기존 인터페이스 호환)
    // =====================================
    
    @Override
    public Mono<String> call(Prompt prompt) {
        log.debug("LLMClient.call() 호출 - 기존 인터페이스 호환 모드");
        
        // 기존 Prompt를 ExecutionContext로 변환
        ExecutionContext context = ExecutionContext.from(prompt);
        return execute(context);
    }
    
    @Override
    public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
        log.debug("LLMClient.entity() 호출 - 기존 인터페이스 호환 모드");
        
        ExecutionContext context = ExecutionContext.from(prompt);
        return executeEntity(context, targetType);
    }
    
    @Override
    public Flux<String> stream(Prompt prompt) {
        log.debug("LLMClient.stream() 호출 - 기존 인터페이스 호환 모드");
        
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .streamingMode(true)
                .build();
        return stream(context);
    }
    
    // =====================================
    // ToolCapableLLMClient 구현 (기존 도구 호환)
    // =====================================
    
    @Override
    public Mono<String> callTools(Prompt prompt, List<Object> toolProviders) {
        log.debug("ToolCapableLLMClient.callTools() 호출 - 도구 개수: {}", 
                toolProviders != null ? toolProviders.size() : 0);
        
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolProviders(toolProviders)
                .toolExecutionEnabled(true)
                .build();
        
        return execute(context);
    }
    
    @Override
    public Mono<String> callToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks) {
        log.debug("ToolCapableLLMClient.callToolCallbacks() 호출 - 도구 개수: {}", 
                toolCallbacks != null ? toolCallbacks.length : 0);
        
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolCallbacks(List.of(toolCallbacks))
                .toolExecutionEnabled(true)
                .build();
        
        return execute(context);
    }
    
    @Override
    public Mono<ChatResponse> callToolsResponse(Prompt prompt, List<Object> toolProviders) {
        log.debug("ToolCapableLLMClient.callToolsResponse() 호출");
        
        return Mono.fromCallable(() -> {
            ExecutionContext context = ExecutionContext.builder()
                    .prompt(prompt)
                    .toolProviders(toolProviders)
                    .toolExecutionEnabled(true)
                    .build();
            
            // 모델 선택 및 실행
            ChatModel model = modelSelectionStrategy.selectModel(context);
            ChatClient client = ChatClient.builder(model).build();
            
            // ToolCallback과 도구 제공자 설정
            var promptSpec = client.prompt(prompt);
            if (context.getToolCallbacks() != null && !context.getToolCallbacks().isEmpty()) {
                promptSpec = promptSpec.toolCallbacks(context.getToolCallbacks());
            }
            if (toolProviders != null && !toolProviders.isEmpty()) {
                promptSpec = promptSpec.tools(toolProviders.toArray());
            }
            
            return promptSpec.call().chatResponse();
        });
    }
    
    @Override
    public Mono<ChatResponse> callToolCallbacksResponse(Prompt prompt, ToolCallback[] toolCallbacks) {
        log.debug("ToolCapableLLMClient.callToolCallbacksResponse() 호출");
        
        return Mono.fromCallable(() -> {
            ExecutionContext context = ExecutionContext.builder()
                    .prompt(prompt)
                    .toolCallbacks(List.of(toolCallbacks))
                    .toolExecutionEnabled(true)
                    .build();
            
            ChatModel model = modelSelectionStrategy.selectModel(context);
            ChatClient client = ChatClient.builder(model).build();
            
            // ToolCallback 설정 후 실행
            var promptSpec = client.prompt(prompt);
            if (toolCallbacks != null && toolCallbacks.length > 0) {
                promptSpec = promptSpec.toolCallbacks(toolCallbacks);
            }
            if (context.getToolProviders() != null && !context.getToolProviders().isEmpty()) {
                promptSpec = promptSpec.tools(context.getToolProviders().toArray());
            }
            
            return promptSpec.call().chatResponse();
        });
    }
    
    @Override
    public Flux<String> streamTools(Prompt prompt, List<Object> toolProviders) {
        log.debug("ToolCapableLLMClient.streamTools() 호출 - 스트리밍 도구 실행");
        
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolProviders(toolProviders)
                .toolExecutionEnabled(true)
                .streamingMode(true)
                .build();
        
        return stream(context);
    }
    
    @Override
    public Flux<String> streamToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks) {
        log.debug("ToolCapableLLMClient.streamToolCallbacks() 호출 - 스트리밍 콜백 실행");
        
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolCallbacks(List.of(toolCallbacks))
                .toolExecutionEnabled(true)
                .streamingMode(true)
                .build();
        
        return stream(context);
    }
    
    // =====================================
    // 3계층 보안 시스템 특화 메서드
    // =====================================
    
    /**
     * 3계층 보안 태스크 실행
     */
    public Mono<String> executeSecurityTask(int tier, String prompt, String requestId) {
        log.info("3계층 보안 태스크 실행 - Tier: {}, RequestId: {}", tier, requestId);
        
        ExecutionContext context = ExecutionContext.forTier(tier, new Prompt(prompt))
                .setRequestId(requestId)
                .addMetadata("security.tier", tier)
                .addMetadata("security.timestamp", System.currentTimeMillis());
        
        return execute(context);
    }
    
    /**
     * SOAR 통합 실행
     */
    public Mono<String> executeSoarTask(ExecutionContext.SecurityTaskType taskType, 
                                         Prompt prompt, 
                                         List<ToolCallback> soarTools) {
        log.info("SOAR 태스크 실행 - TaskType: {}", taskType);
        
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .securityTaskType(taskType)
                .toolCallbacks(soarTools)
                .toolExecutionEnabled(true)
                .advisorEnabled(true)
                .build();
        
        // SOAR 태스크는 주로 Layer 3에서 실행
        if (taskType == ExecutionContext.SecurityTaskType.SOAR_AUTOMATION ||
            taskType == ExecutionContext.SecurityTaskType.APPROVAL_WORKFLOW) {
            context.setTier(3);
        }
        
        return execute(context);
    }
    
    /**
     * 성능 메트릭 수집
     */
    public void recordMetrics(ExecutionContext context, long executionTime, boolean success) {
        log.debug("메트릭 기록 - RequestId: {}, 실행시간: {}ms, 성공: {}", 
                context.getRequestId(), executionTime, success);
        
        // TODO: Micrometer를 사용한 메트릭 기록
        // 모델별, 태스크별, 계층별 성능 추적
    }
}