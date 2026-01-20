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


@Slf4j
@RequiredArgsConstructor
public class DefaultStreamingHandler implements StreamingHandler {

    private final TieredLLMProperties tieredLLMProperties;
    
    @Override
    public Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context) {
        log.debug("일반 스트리밍 처리 시작 - RequestId: {}", context.getRequestId());
        
        return Flux.defer(() -> {
            try {
                
                var promptSpec = chatClient.prompt(context.getPrompt());
                
                
                if (context.getChatOptions() != null) {
                    promptSpec = promptSpec.options(context.getChatOptions());
                } else {
                    
                    String modelName = determineModelName(context);
                    Double temperature = determineTemperature(context);

                    if (modelName != null && tieredLLMProperties.isOllamaModel(modelName)) {
                        
                        org.springframework.ai.ollama.api.OllamaOptions ollamaOptions =
                            org.springframework.ai.ollama.api.OllamaOptions.builder()
                                .model(modelName)
                                .temperature(temperature)
                                .build();
                        promptSpec = promptSpec.options(ollamaOptions);
                        log.debug("스트리밍 Ollama 모델 설정: {}, Temperature: {}", modelName, temperature);
                    } else if (context.getTemperature() != null || context.getMaxTokens() != null) {
                        
                        ChatOptions options = ChatOptions.builder()
                            .temperature(temperature)
                            .maxTokens(context.getMaxTokens())
                            .build();
                        promptSpec = promptSpec.options(options);
                    }
                }
                
                
                Flux<String> responseFlux = promptSpec.stream().content();
                
                
                if (context.getTimeoutMs() != null) {
                    responseFlux = responseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
                }
                
                
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
                
                if (!context.getToolCallbacks().isEmpty()) {
                    return handleStreamingWithToolCallbacks(chatClient, context);
                }
                
                
                if (!context.getToolProviders().isEmpty()) {
                    return handleStreamingWithToolProviders(chatClient, context);
                }
                
                
                log.warn("도구 설정이 없습니다. 일반 스트리밍으로 처리합니다.");
                return handleStreaming(chatClient, context);
                
            } catch (Exception e) {
                log.error("도구 스트리밍 초기화 실패 - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }
    
    
    private Flux<String> handleStreamingWithToolCallbacks(ChatClient chatClient, ExecutionContext context) {
        log.debug("ToolCallback 스트리밍 - 콜백 개수: {}", context.getToolCallbacks().size());
        
        
        
        return Flux.fromIterable(context.getToolCallbacks())
            .flatMap(callback -> executeToolCallback(callback, context))
            .reduce("", (accumulated, current) -> accumulated + "\n" + current)
            .flatMapMany(result -> {
                
                String enhancedPrompt = context.getPrompt().getContents() + "\n\nTool Results:\n" + result;
                
                
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
                    .toolExecutionEnabled(false)  
                    .advisorEnabled(context.getAdvisorEnabled())
                    .analysisLevel(context.getAnalysisLevel())  
                    .build();
                
                return handleStreaming(chatClient, enhancedContext);
            })
            .doOnError(error -> log.error("ToolCallback 스트리밍 실패", error));
    }
    
    
    private Flux<String> handleStreamingWithToolProviders(ChatClient chatClient, ExecutionContext context) {
        log.debug("도구 제공자 스트리밍 - 제공자 개수: {}", context.getToolProviders().size());
        
        
        try {
            var promptSpec = chatClient.prompt(context.getPrompt());
            
            
            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            }
            
            Flux<String> responseFlux = promptSpec.stream().content();
            
            
            if (context.getTimeoutMs() != null) {
                responseFlux = responseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
            }
            
            return responseFlux;
            
        } catch (Exception e) {
            log.error("도구 제공자 스트리밍 실패", e);
            return Flux.error(e);
        }
    }
    
    
    private Flux<String> executeToolCallback(ToolCallback callback, ExecutionContext context) {
        return Flux.defer(() -> {
            try {
                log.debug("ToolCallback 실행: {}", callback.getToolDefinition().name());
                
                
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
    
    
    private Flux<String> optimizeForTier(Flux<String> responseFlux, int tier) {
        Integer timeout = tieredLLMProperties.getTimeoutForTier(tier);

        return switch (tier) {
            case 1 -> {
                
                log.debug("Layer 1 스트리밍 최적화: 빠른 응답 (타임아웃: {}ms)", timeout);
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .onErrorReturn("TIMEOUT");  
            }
            case 2 -> {
                
                log.debug("Layer 2 스트리밍 최적화: 균형 (타임아웃: {}ms)", timeout);
                int bufferMs = Math.max(50, timeout / 6);  
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .buffer(Duration.ofMillis(bufferMs))
                    .flatMap(chunks -> Flux.fromIterable(chunks));
            }
            case 3 -> {
                
                log.debug("Layer 3 스트리밍 최적화: 완전한 응답 (타임아웃: {}ms)", timeout);
                int bufferMs = Math.max(100, timeout / 50);  
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
    
    
    private boolean hasToolsEnabled(ExecutionContext context) {
        return Boolean.TRUE.equals(context.getToolExecutionEnabled()) &&
               (!context.getToolCallbacks().isEmpty() || !context.getToolProviders().isEmpty());
    }
    
    
    private String extractToolInput(String promptContent, String toolName) {
        
        
        return promptContent;
    }

    
    private String determineModelName(ExecutionContext context) {
        
        if (context.getPreferredModel() != null) {
            return context.getPreferredModel();
        }

        
        if (context.getAnalysisLevel() != null) {
            int tier = context.getAnalysisLevel().getDefaultTier();
            return tieredLLMProperties.getModelNameForTier(tier);
        }

        
        if (context.getTier() != null) {
            return tieredLLMProperties.getModelNameForTier(context.getTier());
        }

        
        return tieredLLMProperties.getModelNameForTier(2);  
    }

    
    private Double determineTemperature(ExecutionContext context) {
        
        if (context.getTemperature() != null) {
            return context.getTemperature();
        }

        
        Integer tier = context.getEffectiveTier();
        if (tier != null) {
            return tieredLLMProperties.getTemperatureForTier(tier);
        }

        
        return 0.5d;
    }
}