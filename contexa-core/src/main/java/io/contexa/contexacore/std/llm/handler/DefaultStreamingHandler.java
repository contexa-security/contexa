package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class DefaultStreamingHandler implements StreamingHandler {

    private final TieredLLMProperties tieredLLMProperties;
    private final JsonStreamingProcessor jsonStreamingProcessor;
    
    @Override
    public Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context) {
                
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
                                            } else if (context.getTemperature() != null || context.getMaxTokens() != null) {
                        
                        ChatOptions options = ChatOptions.builder()
                            .temperature(temperature)
                            .maxTokens(context.getMaxTokens())
                            .build();
                        promptSpec = promptSpec.options(options);
                    }
                }

                Flux<String> rawResponseFlux = promptSpec.stream().content();

                if (context.getTimeoutMs() != null) {
                    rawResponseFlux = rawResponseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
                }

                Integer effectiveTier = context.getEffectiveTier();
                if (effectiveTier != null) {
                    rawResponseFlux = optimizeForTier(rawResponseFlux, effectiveTier);
                }

                // Process raw streaming through JsonStreamingProcessor for marker handling
                return jsonStreamingProcessor.process(rawResponseFlux)
                        .doOnError(error -> log.error("Streaming error - RequestId: {}", context.getRequestId(), error));

            } catch (Exception e) {
                log.error("Streaming initialization failed - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }
    
    @Override
    public Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context) {
                
        if (!hasToolsEnabled(context)) {
            log.error("Tools not enabled. Falling back to standard streaming.");
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

                log.error("No tool configuration found. Processing with standard streaming.");
                return handleStreaming(chatClient, context);

            } catch (Exception e) {
                log.error("Tool streaming initialization failed - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }

    private Flux<String> handleStreamingWithToolCallbacks(ChatClient chatClient, ExecutionContext context) {

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
                    .securityTaskType(context.getSecurityTaskType())
                    .tier(context.getTier())
                    .timeoutMs(context.getTimeoutMs())
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
            .doOnError(error -> log.error("ToolCallback streaming failed", error));
    }

    private Flux<String> handleStreamingWithToolProviders(ChatClient chatClient, ExecutionContext context) {

        try {
            var promptSpec = chatClient.prompt(context.getPrompt());

            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            }

            Flux<String> rawResponseFlux = promptSpec.stream().content();

            if (context.getTimeoutMs() != null) {
                rawResponseFlux = rawResponseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
            }

            // Process raw streaming through JsonStreamingProcessor for marker handling
            return jsonStreamingProcessor.process(rawResponseFlux)
                    .doOnError(error -> log.error("Tool provider streaming error - RequestId: {}",
                            context.getRequestId(), error));

        } catch (Exception e) {
            log.error("Tool provider streaming failed", e);
            return Flux.error(e);
        }
    }

    private Flux<String> executeToolCallback(ToolCallback callback, ExecutionContext context) {
        return Flux.defer(() -> {
            try {

                String input = extractToolInput(context.getPrompt().getContents(), callback.getToolDefinition().name());
                String result = callback.call(input);

                String formattedResult = String.format("[%s] %s", callback.getToolDefinition().name(), result);
                return Flux.just(formattedResult);
                
            } catch (Exception e) {
                log.error("ToolCallback execution failed: {}", callback.getToolDefinition().name(), e);
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
                
                                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .onErrorReturn("TIMEOUT");  
            }
            case 2 -> {
                
                                int bufferMs = Math.max(50, timeout / 6);  
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .buffer(Duration.ofMillis(bufferMs))
                    .flatMap(chunks -> Flux.fromIterable(chunks));
            }
            case 3 -> {
                
                                int bufferMs = Math.max(100, timeout / 50);  
                yield responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .buffer(Duration.ofMillis(bufferMs))
                    .flatMap(chunks -> Flux.fromIterable(chunks));
            }
            default -> {
                log.error("Unknown tier: {}, using default streaming", tier);
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