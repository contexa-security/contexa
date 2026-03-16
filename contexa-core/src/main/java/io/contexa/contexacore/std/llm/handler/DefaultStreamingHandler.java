package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class DefaultStreamingHandler implements StreamingHandler {

    private final TieredLLMProperties tieredLLMProperties;
    private final JsonStreamingProcessor jsonStreamingProcessor;

    @Override
    public Flux<String> handleStreaming(ChatClient chatClient, ExecutionContext context, ChatModel selectedModel) {

        return Flux.defer(() -> {
            try {

                var promptSpec = chatClient.prompt(context.getPrompt());
                promptSpec = applyExecutionOptions(promptSpec, context, selectedModel);

                Flux<String> rawResponseFlux = promptSpec.stream().content();

                if (context.getTimeoutMs() != null) {
                    rawResponseFlux = rawResponseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
                }

                Integer effectiveTier = context.getEffectiveTier();
                if (effectiveTier != null) {
                    rawResponseFlux = optimizeForTier(rawResponseFlux, effectiveTier);
                }

                return jsonStreamingProcessor.process(rawResponseFlux)
                        .doOnError(error -> log.error("Streaming error - RequestId: {}", context.getRequestId(), error));

            } catch (Exception e) {
                log.error("Streaming initialization failed - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }

    @Override
    public Flux<String> handleStreamingWithTools(ChatClient chatClient, ExecutionContext context, ChatModel selectedModel) {

        if (!hasToolsEnabled(context)) {
            log.error("Tools not enabled. Falling back to standard streaming.");
            return handleStreaming(chatClient, context, selectedModel);
        }

        return Flux.defer(() -> {
            try {

                if (!context.getToolCallbacks().isEmpty()) {
                    return handleStreamingWithToolCallbacks(chatClient, context, selectedModel);
                }

                if (!context.getToolProviders().isEmpty()) {
                    return handleStreamingWithToolProviders(chatClient, context, selectedModel);
                }

                log.error("No tool configuration found. Processing with standard streaming.");
                return handleStreaming(chatClient, context, selectedModel);

            } catch (Exception e) {
                log.error("Tool streaming initialization failed - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }

    private Flux<String> handleStreamingWithToolCallbacks(ChatClient chatClient,
                                                          ExecutionContext context,
                                                          ChatModel selectedModel) {

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
                            .topP(context.getTopP())
                            .maxTokens(context.getMaxTokens())
                            .metadata(context.getMetadata())
                            .streamingMode(context.getStreamingMode())
                            .toolExecutionEnabled(false)
                            .advisorEnabled(context.getAdvisorEnabled())
                            .analysisLevel(context.getAnalysisLevel())
                            .build();

                    return handleStreaming(chatClient, enhancedContext, selectedModel);
                })
                .doOnError(error -> log.error("ToolCallback streaming failed", error));
    }

    private Flux<String> handleStreamingWithToolProviders(ChatClient chatClient,
                                                          ExecutionContext context,
                                                          ChatModel selectedModel) {

        try {
            var promptSpec = chatClient.prompt(context.getPrompt());
            promptSpec = applyExecutionOptions(promptSpec, context, selectedModel);

            Flux<String> rawResponseFlux = promptSpec.stream().content();

            if (context.getTimeoutMs() != null) {
                rawResponseFlux = rawResponseFlux.timeout(Duration.ofMillis(context.getTimeoutMs()));
            }

            return jsonStreamingProcessor.process(rawResponseFlux)
                    .doOnError(error -> log.error("Tool provider streaming error - RequestId: {}",
                            context.getRequestId(), error));

        } catch (Exception e) {
            log.error("Tool provider streaming failed", e);
            return Flux.error(e);
        }
    }

    private ChatClient.ChatClientRequestSpec applyExecutionOptions(ChatClient.ChatClientRequestSpec promptSpec,
                                                                   ExecutionContext context,
                                                                   ChatModel selectedModel) {

        if (context.getChatOptions() != null) {
            return promptSpec.options(context.getChatOptions());
        }

        if (!hasRuntimeOptions(context)) {
            return promptSpec;
        }

        if (selectedModel instanceof OllamaChatModel ollamaChatModel) {
            return promptSpec.options(buildOllamaOptions(context, ollamaChatModel));
        }

        return promptSpec.options(buildGenericChatOptions(context));
    }

    private boolean hasRuntimeOptions(ExecutionContext context) {
        return context.getTemperature() != null
                || context.getTopP() != null
                || context.getMaxTokens() != null
                || context.getPreferredModel() != null
                || context.getTier() != null
                || context.getAnalysisLevel() != null
                || context.getSecurityTaskType() != null;
    }

    private OllamaChatOptions buildOllamaOptions(ExecutionContext context, OllamaChatModel selectedModel) {
        String modelName = determineModelName(context);
        ChatOptions defaultOptions = selectedModel.getDefaultOptions();
        OllamaChatOptions options = defaultOptions instanceof OllamaChatOptions ollamaDefaults
                ? OllamaChatOptions.fromOptions(ollamaDefaults)
                : OllamaChatOptions.builder().build();

        if (modelName != null && !modelName.isBlank()) {
            options.setModel(modelName);
        }
        if (context.getTemperature() != null) {
            options.setTemperature(context.getTemperature());
        }
        if (context.getTopP() != null) {
            options.setTopP(context.getTopP());
        }
        if (context.getMaxTokens() != null) {
            options.setNumPredict(context.getMaxTokens());
        }

        return options;
    }

    private ChatOptions buildGenericChatOptions(ExecutionContext context) {
        ChatOptions.Builder optionsBuilder = ChatOptions.builder();

        if (context.getTemperature() != null) {
            optionsBuilder.temperature(context.getTemperature());
        }
        if (context.getTopP() != null) {
            optionsBuilder.topP(context.getTopP());
        }
        if (context.getMaxTokens() != null) {
            optionsBuilder.maxTokens(context.getMaxTokens());
        }

        return optionsBuilder.build();
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
            case 1 -> responseFlux
                    .timeout(Duration.ofMillis(timeout))
                    .onErrorReturn("TIMEOUT");
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
        return Boolean.TRUE.equals(context.getToolExecutionEnabled())
                && (!context.getToolCallbacks().isEmpty() || !context.getToolProviders().isEmpty());
    }

    private String extractToolInput(String promptContent, String toolName) {
        if (promptContent == null || toolName == null) {
            return promptContent;
        }

        int toolStartIndex = promptContent.indexOf(toolName);
        if (toolStartIndex == -1) {
            return promptContent;
        }

        int inputStartIndex = promptContent.indexOf("{", toolStartIndex);
        if (inputStartIndex == -1) {
            return promptContent;
        }

        int braceCount = 0;
        int inputEndIndex = inputStartIndex;

        for (int i = inputStartIndex; i < promptContent.length(); i++) {
            char c = promptContent.charAt(i);
            if (c == '{') {
                braceCount++;
            } else if (c == '}') {
                braceCount--;
            }

            if (braceCount == 0) {
                inputEndIndex = i + 1;
                break;
            }
        }

        if (braceCount != 0) {
            return promptContent;
        }

        return promptContent.substring(inputStartIndex, inputEndIndex);
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
}