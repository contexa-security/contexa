package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
public class UnifiedLLMOrchestrator implements LLMOperations, ToolCapableLLMClient {

    private final ModelSelectionStrategy modelSelectionStrategy;
    private final StreamingHandler streamingHandler;
    private final TieredLLMProperties tieredLLMProperties;
    private final AdvisorRegistry advisorRegistry;

    private final ConcurrentHashMap<ChatModel, ChatClient> chatClientCache = new ConcurrentHashMap<>();
    private volatile List<Advisor> cachedAdvisorSnapshot = List.of();

    @Override
    public Mono<String> execute(ExecutionContext context) {

        if (context == null) {
            return Mono.error(new IllegalArgumentException("ExecutionContext cannot be null"));
        }
        if (context.getPrompt() == null) {
            return Mono.error(new IllegalArgumentException("Prompt cannot be null"));
        }

        return Mono.fromCallable(() -> {

                    ChatModel selectedModel = modelSelectionStrategy.selectModel(context);

                    if (selectedModel == null) {
                        throw new IllegalStateException(
                                "No LLM model configured. " +
                                        "Please check spring.ai.ollama.*, spring.ai.anthropic.*, or spring.ai.openai.* settings.");
                    }

                    ChatClient chatClient = buildChatClientWithAdvisors(selectedModel);

                    ChatClient.ChatClientRequestSpec promptSpec = chatClient.prompt(context.getPrompt());

                    String eventUserId = context.getUserId();
                    String eventSessionId = context.getSessionId();
                    if ((eventUserId != null && !eventUserId.isEmpty()) || (eventSessionId != null && !eventSessionId.isEmpty())) {
                        promptSpec = promptSpec.advisors(spec -> {
                            if (eventUserId != null && !eventUserId.isEmpty()) {
                                spec.param("event.userId", eventUserId);
                            }
                            if (eventSessionId != null && !eventSessionId.isEmpty()) {
                                spec.param("event.sessionId", eventSessionId);
                            }
                        });
                    }

                    promptSpec = applyExecutionOptions(promptSpec, context, selectedModel);

                    if (context.getToolExecutionEnabled() != null && context.getToolExecutionEnabled()) {

                        if (context.getToolCallbacks() != null && !context.getToolCallbacks().isEmpty()) {
                            promptSpec = promptSpec.toolCallbacks(context.getToolCallbacks());
                        } else if (context.getToolProviders() != null && !context.getToolProviders().isEmpty()) {
                            promptSpec = promptSpec.tools(context.getToolProviders().toArray());
                        }
                    }

                    String response = promptSpec.call().content();

                    if (response == null || response.isBlank()) {
                        log.error("LLM response is null or empty - RequestId: {}", context.getRequestId());
                        return "{}";
                    }

                    return response;
                })

                .retryWhen(reactor.util.retry.Retry.backoff(2, java.time.Duration.ofSeconds(1))
                        .filter(throwable -> throwable instanceof java.io.IOException)
                        .doBeforeRetry(retrySignal -> log.error("LLM Retry #{} - RequestId: {}, Error: {}",
                                retrySignal.totalRetries() + 1, context.getRequestId(),
                                retrySignal.failure().getMessage())))
                .doOnError(error -> log.error("LLM execution failed - RequestId: {}", context.getRequestId(), error));
    }

    @Override
    public Flux<String> stream(ExecutionContext context) {

        return Flux.defer(() -> {
            try {

                ChatModel selectedModel = modelSelectionStrategy.selectModel(context);

                if (selectedModel == null) {
                    return Flux.error(new IllegalStateException(
                            "LLM model not configured. " +
                                    "Check spring.ai.ollama.*, spring.ai.anthropic.*, or spring.ai.openai.* settings."));
                }

                ChatClient chatClient = buildChatClientWithAdvisors(selectedModel);

                return streamingHandler.handleStreaming(chatClient, context, selectedModel);
            } catch (Exception e) {
                log.error("LLM Streaming failed - RequestId: {}", context.getRequestId(), e);
                return Flux.error(e);
            }
        });
    }

    @Override
    public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {

        if (context == null || context.getPrompt() == null) {
            return Mono.error(new IllegalArgumentException("ExecutionContext and Prompt cannot be null"));
        }
        if (targetType == null) {
            return Mono.error(new IllegalArgumentException("Target type cannot be null"));
        }

        return Mono.fromCallable(() -> {

                    ChatModel selectedModel = modelSelectionStrategy.selectModel(context);

                    if (selectedModel == null) {
                        throw new IllegalStateException(
                                "No LLM model configured. " +
                                        "Please check spring.ai.ollama.*, spring.ai.anthropic.*, or spring.ai.openai.* settings.");
                    }

                    ChatClient chatClient = buildChatClientWithAdvisors(selectedModel);

                    var promptSpec = chatClient.prompt(context.getPrompt());

                    String eventUserId = context.getUserId();
                    String eventSessionId = context.getSessionId();
                    if ((eventUserId != null && !eventUserId.isEmpty()) || (eventSessionId != null && !eventSessionId.isEmpty())) {
                        promptSpec = promptSpec.advisors(spec -> {
                            if (eventUserId != null && !eventUserId.isEmpty()) {
                                spec.param("event.userId", eventUserId);
                            }
                            if (eventSessionId != null && !eventSessionId.isEmpty()) {
                                spec.param("event.sessionId", eventSessionId);
                            }
                        });
                    }

                    promptSpec = applyExecutionOptions(promptSpec, context, selectedModel);

                    return (T) promptSpec.call().entity(targetType);
                })
                .doOnError(error -> log.error("LLM Entity execution failed - RequestId: {}", context.getRequestId(),
                        error));
    }

    private String determineOllamaModelName(ExecutionContext context) {

        if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
            return context.getPreferredModel();
        }

        if (context.getAnalysisLevel() != null) {
            int tier = context.getAnalysisLevel().getDefaultTier();
            return tieredLLMProperties.getModelNameForTier(tier);
        }

        if (context.getTier() != null) {
            return tieredLLMProperties.getModelNameForTier(context.getTier());
        }

        if (context.getSecurityTaskType() != null) {
            int tier = context.getSecurityTaskType().getDefaultTier();
            return tieredLLMProperties.getModelNameForTier(tier);
        }

        String defaultModel = tieredLLMProperties.getModelNameForTier(1);
        log.error("Model selection unavailable, using default model: {}", defaultModel);
        return defaultModel;
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
        String modelName = determineOllamaModelName(context);
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
    @Override
    public Mono<String> call(Prompt prompt) {

        ExecutionContext context = ExecutionContext.from(prompt);
        return execute(context);
    }

    @Override
    public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {

        ExecutionContext context = ExecutionContext.from(prompt);
        return executeEntity(context, targetType);
    }

    @Override
    public Flux<String> stream(Prompt prompt) {

        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .streamingMode(true)
                .build();
        return stream(context);
    }

    @Override
    public Mono<String> callTools(Prompt prompt, List<Object> toolProviders) {

        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolProviders(toolProviders)
                .toolExecutionEnabled(true)
                .build();

        return execute(context);
    }

    @Override
    public Mono<String> callToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks) {

        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolCallbacks(List.of(toolCallbacks))
                .toolExecutionEnabled(true)
                .build();

        return execute(context);
    }

    @Override
    public Mono<ChatResponse> callToolsResponse(Prompt prompt, List<Object> toolProviders) {

        return Mono.fromCallable(() -> {
            ExecutionContext context = ExecutionContext.builder()
                    .prompt(prompt)
                    .toolProviders(toolProviders)
                    .toolExecutionEnabled(true)
                    .build();

            ChatModel model = modelSelectionStrategy.selectModel(context);

            if (model == null) {
                throw new IllegalStateException(
                        "No LLM model configured. " +
                                "Please check spring.ai.ollama.*, spring.ai.anthropic.*, or spring.ai.openai.* settings.");
            }

            ChatClient client = buildChatClientWithAdvisors(model);

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

        return Mono.fromCallable(() -> {
            ExecutionContext context = ExecutionContext.builder()
                    .prompt(prompt)
                    .toolCallbacks(List.of(toolCallbacks))
                    .toolExecutionEnabled(true)
                    .build();

            ChatModel model = modelSelectionStrategy.selectModel(context);

            if (model == null) {
                throw new IllegalStateException(
                        "No LLM model configured. " +
                                "Please check spring.ai.ollama.*, spring.ai.anthropic.*, or spring.ai.openai.* settings.");
            }

            ChatClient client = buildChatClientWithAdvisors(model);

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

        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolCallbacks(List.of(toolCallbacks))
                .toolExecutionEnabled(true)
                .streamingMode(true)
                .build();

        return stream(context);
    }

    private ChatClient buildChatClientWithAdvisors(ChatModel model) {
        List<Advisor> currentAdvisors = advisorRegistry.getEnabled();

        if (!currentAdvisors.equals(cachedAdvisorSnapshot)) {
            chatClientCache.clear();
            cachedAdvisorSnapshot = List.copyOf(currentAdvisors);
        }

        return chatClientCache.computeIfAbsent(model, m -> {
            ChatClient.Builder builder = ChatClient.builder(m);
            if (!currentAdvisors.isEmpty()) {
                builder = builder.defaultAdvisors(currentAdvisors.toArray(new Advisor[0]));
            }
            return builder.build();
        });
    }
}