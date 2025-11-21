package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.time.Duration;

/**
 * 기본 스트리밍 핸들러 구현
 * 
 * 기능:
 * - 일반 스트리밍 처리
 * - 도구 실행이 포함된 스트리밍
 * - 타임아웃 및 에러 처리
 * - 3계층 시스템 최적화
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultStreamingHandler implements StreamingHandler {

    private final TieredLLMProperties tieredLLMProperties;
    
    @Override
    public Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context) {
        log.debug("일반 스트리밍 처리 시작 - RequestId: {}", context.getRequestId());
        
        return Flux.defer(() -> {
            try {
                // ChatClient 프롬프트 스펙 생성 - 올바른 Spring AI API 사용
                var promptSpec = chatClient.prompt(context.getPrompt());
                
                // 옵션 적용 (tier 기반 모델 선택 포함)
                if (context.getChatOptions() != null) {
                    promptSpec = promptSpec.options(context.getChatOptions());
                } else {
                    // 모델 선택 (설정 파일 기반)
                    String modelName = determineModelName(context);
                    Double temperature = determineTemperature(context);

                    if (modelName != null && tieredLLMProperties.isOllamaModel(modelName)) {
                        // Ollama 모델인 경우
                        org.springframework.ai.ollama.api.OllamaOptions ollamaOptions =
                            org.springframework.ai.ollama.api.OllamaOptions.builder()
                                .model(modelName)
                                .temperature(temperature)
                                .build();
                        promptSpec = promptSpec.options(ollamaOptions);
                        log.debug("스트리밍 Ollama 모델 설정: {}, Temperature: {}", modelName, temperature);
                    } else if (context.getTemperature() != null || context.getMaxTokens() != null) {
                        // 기타 모델 (Claude, GPT 등)
                        ChatOptions options = ChatOptions.builder()
                            .temperature(temperature)
                            .maxTokens(context.getMaxTokens())
                            .build();
                        promptSpec = promptSpec.options(options);
                    }
                }
                
                // 스트리밍 실행
                Flux<String> responseFlux = promptSpec.stream().content();
                
                // 타임아웃 적용
                if (context.getTimeoutMs() != null) {
                    responseFlux = responseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
                }
                
                // 3계층 시스템별 최적화 (AnalysisLevel 포함)
                Integer effectiveTier = context.getEffectiveTier();
                if (effectiveTier != null) {
                    responseFlux = optimizeForTier(responseFlux, effectiveTier);
                }
                
                return responseFlux
                    .doOnNext(chunk -> log.trace("스트리밍 청크 수신 - RequestId: {}, 길이: {}", 
                            context.getRequestId(), chunk.length()))
                    .doOnComplete(() -> log.debug("스트리밍 완료 - RequestId: {}", context.getRequestId()))
                    .doOnError(error -> log.error("스트리밍 오류 - RequestId: {}", context.getRequestId(), error));
                
            } catch (Exception e) {
                log.error("스트리밍 초기화 실패 - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }
    
    @Override
    public Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context) {
        log.debug("도구 실행 스트리밍 처리 시작 - RequestId: {}", context.getRequestId());
        
        if (!hasToolsEnabled(context)) {
            log.warn("도구가 활성화되지 않았습니다. 일반 스트리밍으로 대체합니다.");
            return handleStreaming(chatClient, context);
        }
        
        return Flux.defer(() -> {
            try {
                // 도구 콜백이 있는 경우
                if (!context.getToolCallbacks().isEmpty()) {
                    return handleStreamingWithToolCallbacks(chatClient, context);
                }
                
                // 도구 제공자가 있는 경우
                if (!context.getToolProviders().isEmpty()) {
                    return handleStreamingWithToolProviders(chatClient, context);
                }
                
                // 도구가 없으면 일반 스트리밍
                log.warn("도구 설정이 없습니다. 일반 스트리밍으로 처리합니다.");
                return handleStreaming(chatClient, context);
                
            } catch (Exception e) {
                log.error("도구 스트리밍 초기화 실패 - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }
    
    /**
     * ToolCallback을 사용한 스트리밍
     */
    private Flux<String> handleStreamingWithToolCallbacks(ChatClient chatClient, ExecutionContext context) {
        log.debug("ToolCallback 스트리밍 - 콜백 개수: {}", context.getToolCallbacks().size());
        
        // 현재 Spring AI에서 ToolCallback을 사용한 직접적인 스트리밍은 제한적
        // 대신 비동기 실행 후 결과를 스트리밍으로 변환
        return Flux.fromIterable(context.getToolCallbacks())
            .flatMap(callback -> executeToolCallback(callback, context))
            .reduce("", (accumulated, current) -> accumulated + "\n" + current)
            .flatMapMany(result -> {
                // 도구 실행 결과를 포함하여 최종 LLM 호출
                String enhancedPrompt = context.getPrompt().getContents() + "\n\nTool Results:\n" + result;
                
                // 새로운 ExecutionContext 생성 (toBuilder 대신)
                ExecutionContext enhancedContext = ExecutionContext.builder()
                    .prompt(new Prompt(enhancedPrompt))
                    .requestId(context.getRequestId())
                    .userId(context.getUserId())
                    .sessionId(context.getSessionId())
                    .preferredModel(context.getPreferredModel())
                    .taskType(context.getTaskType())
                    .securityTaskType(context.getSecurityTaskType())
                    .tier(context.getTier())
                    .timeoutMs(context.getTimeoutMs())
                    .requireFastResponse(context.getRequireFastResponse())
                    .preferLocalModel(context.getPreferLocalModel())
                    .preferCloudModel(context.getPreferCloudModel())
                    .advisors(context.getAdvisors())
                    .chatOptions(context.getChatOptions())
                    .temperature(context.getTemperature())
                    .maxTokens(context.getMaxTokens())
                    .metadata(context.getMetadata())
                    .streamingMode(context.getStreamingMode())
                    .toolExecutionEnabled(false)  // 무한 루프 방지
                    .advisorEnabled(context.getAdvisorEnabled())
                    .analysisLevel(context.getAnalysisLevel())  // AnalysisLevel 추가
                    .build();
                
                return handleStreaming(chatClient, enhancedContext);
            })
            .doOnError(error -> log.error("ToolCallback 스트리밍 실패", error));
    }
    
    /**
     * 도구 제공자를 사용한 스트리밍
     */
    private Flux<String> handleStreamingWithToolProviders(ChatClient chatClient, ExecutionContext context) {
        log.debug("도구 제공자 스트리밍 - 제공자 개수: {}", context.getToolProviders().size());
        
        // 도구 제공자 기반 스트리밍은 ChatClient의 기본 기능 활용
        try {
            var promptSpec = chatClient.prompt(context.getPrompt());
            
            // 옵션 적용
            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            }
            
            Flux<String> responseFlux = promptSpec.stream().content();
            
            // 타임아웃 적용
            if (context.getTimeoutMs() != null) {
                responseFlux = responseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
            }
            
            return responseFlux;
            
        } catch (Exception e) {
            log.error("도구 제공자 스트리밍 실패", e);
            return Flux.error(e);
        }
    }
    
    /**
     * 개별 ToolCallback 실행
     */
    private Flux<String> executeToolCallback(ToolCallback callback, ExecutionContext context) {
        return Flux.defer(() -> {
            try {
                log.debug("ToolCallback 실행: {}", callback.getToolDefinition().name());
                
                // 간단한 입력으로 도구 실행 (실제로는 더 정교한 입력 파싱 필요)
                String input = extractToolInput(context.getPrompt().getContents(), callback.getToolDefinition().name());
                String result = callback.call(input);
                
                log.debug("ToolCallback 실행 완료: {} -> 결과 길이: {}", 
                        callback.getToolDefinition().name(), result != null ? result.length() : 0);
                
                String formattedResult = String.format("[%s] %s", callback.getToolDefinition().name(), result);
                return Flux.just(formattedResult);
                
            } catch (Exception e) {
                log.error("ToolCallback 실행 실패: {}", callback.getToolDefinition().name(), e);
                String errorResult = String.format("[%s] Error: %s", callback.getToolDefinition().name(), e.getMessage());
                return Flux.just(errorResult);
            }
        })
        .onErrorReturn("Tool execution failed");
    }
    
    /**
     * 3계층 시스템별 스트리밍 최적화 (설정 파일 기반)
     */
    private Flux<String> optimizeForTier(Flux<String> responseFlux, int tier) {
        Integer timeout = tieredLLMProperties.getTimeoutForTier(tier);

        return switch (tier) {
            case 1 -> {
                // Layer 1: 빠른 응답을 위한 버퍼링 최소화
                log.debug("Layer 1 스트리밍 최적화: 빠른 응답 (타임아웃: {}ms)", timeout);
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .onErrorReturn("TIMEOUT");  // 타임아웃 시 기본 응답
            }
            case 2 -> {
                // Layer 2: 균형잡힌 스트리밍
                log.debug("Layer 2 스트리밍 최적화: 균형 (타임아웃: {}ms)", timeout);
                int bufferMs = Math.max(50, timeout / 6);  // 타임아웃의 1/6을 버퍼로
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .buffer(Duration.ofMillis(bufferMs))
                    .flatMap(chunks -> Flux.fromIterable(chunks));
            }
            case 3 -> {
                // Layer 3: 완전한 응답을 위한 충분한 시간
                log.debug("Layer 3 스트리밍 최적화: 완전한 응답 (타임아웃: {}ms)", timeout);
                int bufferMs = Math.max(100, timeout / 50);  // 타임아웃의 1/50을 버퍼로
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .buffer(Duration.ofMillis(bufferMs))
                    .flatMap(chunks -> Flux.fromIterable(chunks));
            }
            default -> {
                log.warn("알 수 없는 tier: {}, 기본 스트리밍 사용", tier);
                yield responseFlux.timeout(Duration.ofMillis(1000));
            }
        };
    }
    
    /**
     * 도구가 활성화되어 있는지 확인
     */
    private boolean hasToolsEnabled(ExecutionContext context) {
        return Boolean.TRUE.equals(context.getToolExecutionEnabled()) &&
               (!context.getToolCallbacks().isEmpty() || !context.getToolProviders().isEmpty());
    }
    
    /**
     * 프롬프트에서 특정 도구에 대한 입력 추출 (간단한 구현)
     */
    private String extractToolInput(String promptContent, String toolName) {
        // 실제로는 더 정교한 파싱이 필요
        // 여기서는 간단하게 프롬프트 전체를 입력으로 사용
        return promptContent;
    }

    /**
     * 컨텍스트에서 모델명 결정 (설정 파일 기반)
     */
    private String determineModelName(ExecutionContext context) {
        // 1. 명시적 지정
        if (context.getPreferredModel() != null) {
            return context.getPreferredModel();
        }

        // 2. AnalysisLevel 기반
        if (context.getAnalysisLevel() != null) {
            int tier = context.getAnalysisLevel().getDefaultTier();
            return tieredLLMProperties.getModelNameForTier(tier);
        }

        // 3. Tier 기반
        if (context.getTier() != null) {
            return tieredLLMProperties.getModelNameForTier(context.getTier());
        }

        // 4. 기본값
        return tieredLLMProperties.getModelNameForTier(2);  // Layer 2 기본
    }

    /**
     * 컨텍스트에서 Temperature 결정 (설정 파일 기반)
     */
    private Double determineTemperature(ExecutionContext context) {
        // 1. 명시적 지정
        if (context.getTemperature() != null) {
            return context.getTemperature();
        }

        // 2. Tier 기반
        Integer tier = context.getEffectiveTier();
        if (tier != null) {
            return tieredLLMProperties.getTemperatureForTier(tier);
        }

        // 3. 기본값
        return 0.5d;
    }
}