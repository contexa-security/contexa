/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionOutputParser;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.client.AdvisorParams;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.ResponseEntity;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

@Slf4j
@RequiredArgsConstructor
public class UnifiedLLMOrchestrator implements LLMOperations, ToolCapableLLMClient {

    private final ModelSelectionStrategy modelSelectionStrategy;
    private final StreamingHandler streamingHandler;
    private final TieredLLMProperties tieredLLMProperties;
    private final AdvisorRegistry advisorRegistry;

    private final ConcurrentHashMap<ChatModel, ChatClient> chatClientCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<ChatModel, ChatClient> chatClientNoAdvisorCache = new ConcurrentHashMap<>();
    private final SecurityDecisionOutputParser securityDecisionOutputParser = new SecurityDecisionOutputParser();
    private volatile List<Advisor> cachedAdvisorSnapshot = List.of();

    private static final List<String> SECURITY_DECISION_PARSER_METADATA_KEYS = List.of(
            "securityDecisionParsingMode",
            "securityDecisionRawOutputHash",
            "securityDecisionRawOutputLength",
            "securityDecisionCoreFieldsPresent",
            "securityDecisionParsingFallbackApplied",
            "syntheticSecurityDecisionApplied",
            "llmDecisionPresent",
            "securityDecisionFallbackApplied",
            "securityDecisionOutputRepairApplied",
            "securityDecisionOutputRepairFields",
            "securityDecisionParseFailureCategory",
            "securityDecisionFallbackAction",
            "structuredOutputFailureCategory"
    );

    @Override
    public Mono<String> execute(ExecutionContext context) {

        if (context == null) {
            return Mono.error(new IllegalArgumentException("ExecutionContext cannot be null"));
        }
        if (context.getPrompt() == null) {
            return Mono.error(new IllegalArgumentException("Prompt cannot be null"));
        }

        Mono<String> execution = Mono.fromCallable(() -> {
                    ChatResponse chatResponse = executeForChatResponse(context);
                    String response = extractResponseText(chatResponse);
                    if (response == null || response.isBlank()) {
                        String requestId = context.getRequestId();
                        log.error("LLM response is null or empty - RequestId: {}", requestId);
                        throw new IllegalStateException("LLM response is null or empty"
                                + (requestId != null && !requestId.isBlank() ? " - RequestId: " + requestId : ""));
                    }
                    return response;
                })
                .doOnError(error -> log.error("LLM execution failed - RequestId: {}", context.getRequestId(), error));

        if (isRetryDisabled(context)) {
            return execution;
        }

        return execution.retryWhen(Retry.backoff(2, Duration.ofSeconds(1))
                .filter(throwable -> throwable instanceof IOException)
                .doBeforeRetry(retrySignal -> log.error("LLM Retry #{} - RequestId: {}, Error: {}",
                        retrySignal.totalRetries() + 1, context.getRequestId(),
                        retrySignal.failure().getMessage())));
    }

    @Override
    public Flux<String> stream(ExecutionContext context) {

        return Flux.defer(() -> {
            try {

                ChatModel selectedModel = modelSelectionStrategy.selectModel(context);

                if (selectedModel == null) {
                    return Flux.error(new IllegalStateException(
                            "LLM model not configured. " +
                                    "Add at least one Spring AI chat provider starter to the application dependencies, configure the matching provider under spring.ai.*, and ensure a ChatModel bean is available to CONTEXA."));
                }

                ChatClient chatClient = buildChatClient(selectedModel, context.getAdvisorEnabled());

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
        if (SecurityDecisionResponseLite.class.equals(targetType)) {
            return executeSecurityDecisionRawGuarded(context, targetType);
        }

        return Mono.fromCallable(() -> {
                    ResponseEntity<ChatResponse, T> responseEntity = executeForResponseEntity(context, targetType);
                    T entity = responseEntity.getEntity();
                    if (entity == null) {
                        throw new IllegalStateException("Structured output entity is null");
                    }
                    return entity;
                })
                .doOnError(error -> log.error("LLM Entity execution failed - RequestId: {}", context.getRequestId(),
                        error))
                .transform(entityExecution -> isRetryDisabled(context)
                        ? entityExecution
                        : entityExecution.retryWhen(Retry.backoff(2, Duration.ofSeconds(1))
                        .filter(throwable -> throwable instanceof IOException)
                        .doBeforeRetry(retrySignal -> log.error("LLM Entity Retry #{} - RequestId: {}, Error: {}",
                                retrySignal.totalRetries() + 1,
                                context.getRequestId(),
                                retrySignal.failure().getMessage()))));
    }

    private <T> Mono<T> executeSecurityDecisionRawGuarded(ExecutionContext context, Class<T> targetType) {
        context.addMetadata("entityExecutionAttempted", false);
        context.addMetadata("entityExecutionSucceeded", false);
        context.addMetadata("rawExecutionAttempted", true);
        context.addMetadata("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED");
        context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
        return execute(context)
                .map(rawResponse -> {
                    context.addMetadata("rawExecutionSucceeded", true);
                    context.addMetadata("structuredOutputComplete", true);
                    return targetType.cast(parseSecurityDecisionRawResponse(rawResponse, context));
                })
                .onErrorResume(error -> {
                    log.error("LLM security decision raw guarded execution failed - RequestId: {}",
                            context.getRequestId(), error);
                    context.addMetadata("rawExecutionSucceeded", false);
                    context.addMetadata("structuredOutputFailureCategory", "MODEL_UNAVAILABLE");
                    context.addMetadata("securityDecisionParseFailureCategory", "MODEL_UNAVAILABLE");
                    context.addMetadata("securityDecisionFallbackReason", "LLM_EXECUTION_FAILED");
                    context.addMetadata("securityDecisionRawExecutionFailureClass", error.getClass().getName());
                    context.addMetadata("securityDecisionRawExecutionFailureMessage", error.getMessage());
                    context.addMetadata("structuredOutputComplete", true);
                    return Mono.just(targetType.cast(parseSecurityDecisionRawResponse("", context)));
                });
    }

    private SecurityDecisionResponseLite parseSecurityDecisionRawResponse(String rawResponse, ExecutionContext context) {
        PipelineExecutionContext parserContext = new PipelineExecutionContext(
                context != null && context.getRequestId() != null ? context.getRequestId() : "security-decision-raw-guarded");
        if (context != null && context.getMetadata() != null) {
            Object existingFailureCategory = context.getMetadata().get("securityDecisionParseFailureCategory");
            if (existingFailureCategory != null) {
                parserContext.addMetadata("securityDecisionParseFailureCategory", existingFailureCategory);
            }
        }
        SecurityDecisionResponseLite response = securityDecisionOutputParser.parse(rawResponse, parserContext);
        copySecurityDecisionParserMetadata(parserContext, context);
        return response;
    }

    private void copySecurityDecisionParserMetadata(PipelineExecutionContext parserContext, ExecutionContext context) {
        if (parserContext == null || context == null) {
            return;
        }
        for (String key : SECURITY_DECISION_PARSER_METADATA_KEYS) {
            Object value = parserContext.getMetadata(key, Object.class);
            if (value != null) {
                context.addMetadata(key, value);
            }
        }
    }

    private ChatClient.ChatClientRequestSpec applyExecutionOptions(ChatClient.ChatClientRequestSpec promptSpec,
                                                                   ExecutionContext context,
                                                                   ChatModel selectedModel) {

        if (context.getChatOptions() != null) {
            return promptSpec.options(ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                    context.getChatOptions(),
                    context,
                    selectedModel));
        }

        if (ProviderAwareChatOptionsFactory.requiresProviderSpecificOptions(context, selectedModel)) {
            return promptSpec.options(ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, selectedModel, tieredLLMProperties));
        }

        if (!hasRuntimeOptions(context)) {
            return promptSpec;
        }

        return promptSpec.options(ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, selectedModel, tieredLLMProperties));
    }

    private ChatResponse executeForChatResponse(ExecutionContext context) {
        ChatModel selectedModel = requireSelectedModel(context);
        ChatClient chatClient = buildChatClient(selectedModel, context.getAdvisorEnabled());
        ChatClient.ChatClientRequestSpec promptSpec = preparePromptSpec(chatClient, context, selectedModel);
        ChatResponse chatResponse = promptSpec.call().chatResponse();
        captureResponseMetadata(context, selectedModel, chatResponse);
        return chatResponse;
    }

    private <T> ResponseEntity<ChatResponse, T> executeForResponseEntity(ExecutionContext context, Class<T> targetType) {
        ChatModel selectedModel = requireSelectedModel(context);
        ChatClient chatClient = buildChatClient(selectedModel, context.getAdvisorEnabled());
        ChatClient.ChatClientRequestSpec promptSpec = preparePromptSpec(chatClient, context, selectedModel);
        ResponseEntity<ChatResponse, T> responseEntity = promptSpec.call().responseEntity(targetType);
        captureResponseMetadata(context, selectedModel, responseEntity.getResponse());
        return responseEntity;
    }

    private ChatModel requireSelectedModel(ExecutionContext context) {
        ChatModel selectedModel = modelSelectionStrategy.selectModel(context);
        if (selectedModel == null) {
            throw new IllegalStateException(
                    "No LLM model configured. " +
                            "Add at least one Spring AI chat provider starter to the application dependencies, configure the matching provider under spring.ai.*, and ensure a ChatModel bean is available to CONTEXA.");
        }
        return selectedModel;
    }

    private ChatClient.ChatClientRequestSpec preparePromptSpec(ChatClient chatClient,
                                                               ExecutionContext context,
                                                               ChatModel selectedModel) {
        ChatClient.ChatClientRequestSpec promptSpec = chatClient.prompt(context.getPrompt());
        promptSpec = applyAdvisorConfiguration(promptSpec, context);
        promptSpec = applyExecutionOptions(promptSpec, context, selectedModel);

        if (Boolean.TRUE.equals(context.getToolExecutionEnabled())) {
            if (context.getToolCallbacks() != null && !context.getToolCallbacks().isEmpty()) {
                promptSpec = promptSpec.toolCallbacks(context.getToolCallbacks());
            } else if (context.getToolProviders() != null && !context.getToolProviders().isEmpty()) {
                promptSpec = promptSpec.tools(context.getToolProviders().toArray());
            }
        }
        return promptSpec;
    }

    private ChatClient.ChatClientRequestSpec applyAdvisorConfiguration(ChatClient.ChatClientRequestSpec promptSpec,
                                                                      ExecutionContext context) {
        if (context == null) {
            return promptSpec;
        }

        boolean advisorEnabled = isAdvisorEnabled(context);
        boolean nativeStructuredOutput = resolveStructuredOutputMode(context) == StructuredOutputMode.NATIVE_STRUCTURED;
        String eventUserId = context.getUserId();
        String eventSessionId = context.getSessionId();
        boolean shouldApplyRuntimeAdvisorParams = nativeStructuredOutput
                || (advisorEnabled && ((eventUserId != null && !eventUserId.isEmpty())
                || (eventSessionId != null && !eventSessionId.isEmpty())));
        if (shouldApplyRuntimeAdvisorParams) {
            promptSpec = promptSpec.advisors(spec -> {
                if (advisorEnabled && eventUserId != null && !eventUserId.isEmpty()) {
                    spec.param("event.userId", eventUserId);
                }
                if (advisorEnabled && eventSessionId != null && !eventSessionId.isEmpty()) {
                    spec.param("event.sessionId", eventSessionId);
                }
                if (nativeStructuredOutput) {
                    AdvisorParams.ENABLE_NATIVE_STRUCTURED_OUTPUT.accept(spec);
                }
            });
        }

        if (context.getAdvisors() != null && !context.getAdvisors().isEmpty()) {
            promptSpec = promptSpec.advisors(context.getAdvisors());
        }
        return promptSpec;
    }

    private StructuredOutputMode resolveStructuredOutputMode(ExecutionContext context) {
        if (context == null || context.getMetadata() == null) {
            return StructuredOutputMode.LEGACY_RAW;
        }
        return StructuredOutputMode.fromValue(
                context.getMetadata().get("structuredOutputMode"),
                StructuredOutputMode.LEGACY_RAW);
    }

    private String extractResponseText(ChatResponse chatResponse) {
        if (chatResponse == null || chatResponse.getResult() == null || chatResponse.getResult().getOutput() == null) {
            return null;
        }
        return chatResponse.getResult().getOutput().getText();
    }

    private void captureResponseMetadata(ExecutionContext context, ChatModel selectedModel, ChatResponse chatResponse) {
        if (context == null) {
            return;
        }
        if (chatResponse == null) {
            context.addMetadata("actualTokenUsageAvailable", false);
            return;
        }

        ChatResponseMetadata metadata = chatResponse.getMetadata();
        if (metadata == null) {
            context.addMetadata("actualTokenUsageAvailable", false);
            return;
        }

        if (metadata.getId() != null && !metadata.getId().isBlank()) {
            context.addMetadata("providerResponseId", metadata.getId());
        }
        String providerModel = metadata.getModel();
        if (providerModel == null || providerModel.isBlank()) {
            providerModel = ProviderAwareChatOptionsFactory.resolveSelectedModelId(context);
        }
        if ((providerModel == null || providerModel.isBlank()) && selectedModel != null) {
            providerModel = selectedModel.getClass().getSimpleName();
        }
        if (providerModel != null && !providerModel.isBlank()) {
            context.addMetadata("providerResponseModel", providerModel);
        }

        Usage usage = metadata.getUsage();
        Integer promptTokens = usage != null ? usage.getPromptTokens() : null;
        Integer completionTokens = usage != null ? usage.getCompletionTokens() : null;
        Integer totalTokens = usage != null ? usage.getTotalTokens() : null;
        boolean usageAvailable = promptTokens != null || completionTokens != null || totalTokens != null;
        context.addMetadata("actualTokenUsageAvailable", usageAvailable);
        if (promptTokens != null) {
            context.addMetadata("actualPromptTokens", promptTokens);
        }
        if (completionTokens != null) {
            context.addMetadata("actualCompletionTokens", completionTokens);
        }
        if (totalTokens != null) {
            context.addMetadata("actualTotalTokens", totalTokens);
        }

        Integer cachedPromptTokens = extractCachedPromptTokens(metadata, usage);
        if (cachedPromptTokens != null) {
            context.addMetadata("cachedPromptTokens", cachedPromptTokens);
            context.addMetadata("promptCacheHit", cachedPromptTokens > 0);
        } else if (context.getMetadata().containsKey("promptCacheEligible")) {
            context.addMetadata("promptCacheHit", false);
        }
    }

    private Integer extractCachedPromptTokens(ChatResponseMetadata metadata, Usage usage) {
        Integer fromUsage = extractCachedPromptTokensFromNativeUsage(usage != null ? usage.getNativeUsage() : null);
        if (fromUsage != null) {
            return fromUsage;
        }
        if (metadata == null) {
            return null;
        }
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            Integer extracted = extractCachedPromptTokensFromUnknown(entry.getValue());
            if (extracted != null) {
                return extracted;
            }
            if (entry.getKey() != null && entry.getKey().toLowerCase(Locale.ROOT).contains("cached")
                    && entry.getValue() instanceof Number number) {
                return number.intValue();
            }
        }
        return null;
    }

    private Integer extractCachedPromptTokensFromNativeUsage(Object nativeUsage) {
        if (nativeUsage == null) {
            return null;
        }
        return extractCachedPromptTokensFromUnknown(nativeUsage);
    }

    @SuppressWarnings("unchecked")
    private Integer extractCachedPromptTokensFromUnknown(Object source) {
        if (source == null) {
            return null;
        }
        if (source instanceof Number number) {
            return number.intValue();
        }
        if (source instanceof Map<?, ?> map) {
            for (String key : List.of("cached_tokens", "cachedTokens")) {
                Object value = map.get(key);
                if (value instanceof Number number) {
                    return number.intValue();
                }
            }
            Object nested = map.get("prompt_tokens_details");
            Integer nestedCached = extractCachedPromptTokensFromUnknown(nested);
            if (nestedCached != null) {
                return nestedCached;
            }
            nested = map.get("promptTokensDetails");
            return extractCachedPromptTokensFromUnknown(nested);
        }
        try {
            Object promptTokensDetails = source.getClass().getMethod("promptTokensDetails").invoke(source);
            Integer cached = extractCachedPromptTokensFromUnknown(promptTokensDetails);
            if (cached != null) {
                return cached;
            }
        } catch (Exception ignored) {
        }
        try {
            Object promptTokensDetails = source.getClass().getMethod("getPromptTokensDetails").invoke(source);
            Integer cached = extractCachedPromptTokensFromUnknown(promptTokensDetails);
            if (cached != null) {
                return cached;
            }
        } catch (Exception ignored) {
        }
        for (String methodName : List.of("cachedTokens", "getCachedTokens")) {
            try {
                Object value = source.getClass().getMethod(methodName).invoke(source);
                if (value instanceof Number number) {
                    return number.intValue();
                }
            } catch (Exception ignored) {
            }
        }
        return null;
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
                                "Add at least one Spring AI chat provider starter to the application dependencies, configure the matching provider under spring.ai.*, and ensure a ChatModel bean is available to CONTEXA.");
            }

            ChatClient client = buildChatClient(model, context.getAdvisorEnabled());

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
                                "Add at least one Spring AI chat provider starter to the application dependencies, configure the matching provider under spring.ai.*, and ensure a ChatModel bean is available to CONTEXA.");
            }

            ChatClient client = buildChatClient(model, context.getAdvisorEnabled());

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

    private ChatClient buildChatClient(ChatModel model, Boolean advisorEnabled) {
        if (!isAdvisorEnabled(advisorEnabled)) {
            return chatClientNoAdvisorCache.computeIfAbsent(model, m -> ChatClient.builder(m).build());
        }

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

    private boolean isAdvisorEnabled(ExecutionContext context) {
        return context == null || isAdvisorEnabled(context.getAdvisorEnabled());
    }

    private boolean isAdvisorEnabled(Boolean advisorEnabled) {
        return !Boolean.FALSE.equals(advisorEnabled);
    }

    private boolean isRetryDisabled(ExecutionContext context) {
        if (context == null || context.getMetadata() == null) {
            return false;
        }
        Object value = context.getMetadata().get("disableRetries");
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        return false;
    }
}

