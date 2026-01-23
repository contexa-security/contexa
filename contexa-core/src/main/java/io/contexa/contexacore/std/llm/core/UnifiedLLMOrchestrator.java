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

@Slf4j
@RequiredArgsConstructor
public class UnifiedLLMOrchestrator implements LLMOperations, ToolCapableLLMClient {

    private final ModelSelectionStrategy modelSelectionStrategy;
    private final StreamingHandler streamingHandler;
    private final TieredLLMProperties tieredLLMProperties;

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

            ChatClient chatClient = ChatClient.builder(selectedModel).build();

            var promptSpec = chatClient.prompt(context.getPrompt());

            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            } else if (context.getTemperature() != null || context.getMaxTokens() != null ||
                    context.getPreferredModel() != null || context.getTier() != null ||
                    context.getAnalysisLevel() != null) {

                if (selectedModel instanceof OllamaChatModel) {
                    String modelName = determineOllamaModelName(context);
                    if (modelName != null) {
                        OllamaOptions ollamaOptions = OllamaOptions.builder()
                                .model(modelName)
                                .temperature(context.getTemperature() != null ? context.getTemperature() : 0.7d)
                                .build();
                        promptSpec = promptSpec.options(ollamaOptions);
                    }
                } else {
                    ChatOptions options = ChatOptions.builder()
                            .temperature(context.getTemperature())
                            .maxTokens(context.getMaxTokens())
                            .build();
                    promptSpec = promptSpec.options(options);
                }
            }

            if (context.getToolExecutionEnabled() != null && context.getToolExecutionEnabled()) {

                if (context.getToolCallbacks() != null && !context.getToolCallbacks().isEmpty()) {
                    promptSpec = promptSpec.toolCallbacks(context.getToolCallbacks());
                } else if (context.getToolProviders() != null && !context.getToolProviders().isEmpty()) {
                    promptSpec = promptSpec.tools(context.getToolProviders().toArray());
                }
            }

            long startTime = System.currentTimeMillis();
            String response = promptSpec.call().content();
            long executionTime = System.currentTimeMillis() - startTime;

            String modelName = selectedModel.getClass().getSimpleName();
            modelSelectionStrategy.recordModelPerformance(modelName, executionTime, response != null);

            if (response == null || response.isBlank()) {
                log.warn("LLM response is null or empty - RequestId: {}", context.getRequestId());
                return "{}";
            }

            return response;
        })

                .retryWhen(reactor.util.retry.Retry.backoff(2, java.time.Duration.ofSeconds(1))
                        .filter(throwable -> throwable instanceof java.io.IOException)
                        .doBeforeRetry(retrySignal -> log.warn("LLM Retry #{} - RequestId: {}, Error: {}",
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

                ChatClient chatClient = ChatClient.builder(selectedModel).build();

                long startTime = System.currentTimeMillis();
                return streamingHandler.handleStreaming(chatClient, context)
                        .doOnComplete(() -> {
                            long executionTime = System.currentTimeMillis() - startTime;
                            String modelName = selectedModel.getClass().getSimpleName();
                            modelSelectionStrategy.recordModelPerformance(modelName, executionTime, true);
                        })
                        .doOnError(error -> {
                            long executionTime = System.currentTimeMillis() - startTime;
                            String modelName = selectedModel.getClass().getSimpleName();
                            modelSelectionStrategy.recordModelPerformance(modelName, executionTime, false);
                            log.error("Streaming failed - model: {}, execution time: {}ms", modelName, executionTime);
                        });
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

            ChatClient chatClient = ChatClient.builder(selectedModel).build();

            var promptSpec = chatClient.prompt(context.getPrompt());

            if (context.getChatOptions() != null) {
                promptSpec = promptSpec.options(context.getChatOptions());
            }

            long startTime = System.currentTimeMillis();
            T result = (T) promptSpec.call().entity(targetType);
            long executionTime = System.currentTimeMillis() - startTime;

            String modelName = selectedModel.getClass().getSimpleName();
            modelSelectionStrategy.recordModelPerformance(modelName, executionTime, result != null);

            return result;
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
            String modelName = tieredLLMProperties.getModelNameForTier(tier);
            return modelName;
        }

        if (context.getTier() != null) {
            String modelName = tieredLLMProperties.getModelNameForTier(context.getTier());
            return modelName;
        }

        if (context.getSecurityTaskType() != null) {
            int tier = context.getSecurityTaskType().getDefaultTier();
            String modelName = tieredLLMProperties.getModelNameForTier(tier);
            return modelName;
        }

        String defaultModel = tieredLLMProperties.getModelNameForTier(1);
        log.warn("Model selection unavailable, using default model: {}", defaultModel);
        return defaultModel;
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

            ChatClient client = ChatClient.builder(model).build();

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

            ChatClient client = ChatClient.builder(model).build();

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

    public Mono<String> executeSecurityTask(int tier, String prompt, String requestId) {

        ExecutionContext context = ExecutionContext.forTier(tier, new Prompt(prompt))
                .setRequestId(requestId)
                .addMetadata("security.tier", tier)
                .addMetadata("security.timestamp", System.currentTimeMillis());

        return execute(context);
    }

    public Mono<String> executeSoarTask(ExecutionContext.SecurityTaskType taskType,
            Prompt prompt,
            List<ToolCallback> soarTools) {

        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .securityTaskType(taskType)
                .toolCallbacks(soarTools)
                .toolExecutionEnabled(true)
                .advisorEnabled(true)
                .build();

        if (taskType == ExecutionContext.SecurityTaskType.SOAR_AUTOMATION ||
                taskType == ExecutionContext.SecurityTaskType.APPROVAL_WORKFLOW) {
            context.setTier(3);
        }

        return execute(context);
    }
}