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

import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties.LlmProviderThrottleSettings;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionOutputParser;
import java.io.IOException;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import io.micrometer.observation.ObservationRegistry;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.client.AdvisorParams;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.ResponseEntity;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;


@Slf4j
@RequiredArgsConstructor
public class UnifiedLLMOrchestrator implements LLMOperations, ToolCapableLLMClient {

    /**
     * Spring AI's exceptions for a provider's HTTP error: a 4xx is non-transient, a 5xx transient (the retry module is
     * not a dependency of the core, so they are told by name).
     */
    private static final String NON_TRANSIENT_AI_EXCEPTION = "org.springframework.ai.retry.NonTransientAiException";
    private static final String TRANSIENT_AI_EXCEPTION = "org.springframework.ai.retry.TransientAiException";
    /** Spring AI's message of a provider's HTTP error: "HTTP 400 - {body}". */
    private static final Pattern HTTP_STATUS = Pattern.compile("^HTTP (\\d{3})\\b");
    /** The 4xx statuses that may pass when the same request is sent again: a timeout, a conflict, a rate limit. */
    private static final Set<Integer> RETRYABLE_CLIENT_STATUSES = Set.of(408, 409, 429);
    private static final int PROVIDER_OVERLOADED_STATUS = 529;
    /** Q-38: a provider's rate limit; retried, and when the retries run out it is the limit, not an outage. */
    private static final int PROVIDER_RATE_LIMITED_STATUS = 429;
    /** The failure message of an answer without text; LLMExecutionStep reads it to tell a cut answer (N-OUT-2). */
    public static final String EMPTY_RESPONSE_MESSAGE = "LLM response is null or empty";

    private final ModelSelectionStrategy modelSelectionStrategy;
    private final StreamingHandler streamingHandler;
    private final TieredLLMProperties tieredLLMProperties;
    private final AdvisorRegistry advisorRegistry;
    private final SecurityPlaneProperties securityPlaneProperties;

    private final ConcurrentHashMap<ChatModel, ChatClient> chatClientCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<ChatModel, ChatClient> chatClientNoAdvisorCache = new ConcurrentHashMap<>();
    private final SecurityDecisionOutputParser securityDecisionOutputParser = new SecurityDecisionOutputParser();
    private volatile List<Advisor> cachedAdvisorSnapshot = List.of();
    private volatile ObservationRegistry observationRegistry = ObservationRegistry.NOOP;
    private final ProviderThrottle providerThrottle = new ProviderThrottle();
    private static final AtomicInteger PROVIDER_CALL_THREAD_SEQUENCE = new AtomicInteger();
    private static final ExecutorService PROVIDER_CALL_EXECUTOR = Executors.newCachedThreadPool(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "contexa-llm-provider-call-" + PROVIDER_CALL_THREAD_SEQUENCE.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    });

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
                    long responseExtractStart = System.currentTimeMillis();
                    String response = extractResponseText(chatResponse);
                    long responseExtractMs = System.currentTimeMillis() - responseExtractStart;
                    context.addMetadata("responseExtractMs", responseExtractMs);
                    if (response == null || response.isBlank()) {
                        String requestId = context.getRequestId();
                        log.error("LLM response is null or empty - RequestId: {}", requestId);
                        throw new IllegalStateException(EMPTY_RESPONSE_MESSAGE
                                + (requestId != null && !requestId.isBlank() ? " - RequestId: " + requestId : ""));
                    }
                    return response;
                })
                .doOnError(error -> log.error("LLM execution failed - RequestId: {}", context.getRequestId(), error));

        if (isRetryDisabled(context)) {
            return execution;
        }

        return execution.retryWhen(llmProviderRetry("LLM", context));
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
                ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(selectedModel);

                ChatClient chatClient = buildChatClient(selectedModel, context.getAdvisorEnabled());

                // A stream asked with tools (streamTools, streamToolCallbacks) goes where the tools are attached.
                return Boolean.TRUE.equals(context.getToolExecutionEnabled())
                        ? streamingHandler.handleStreamingWithTools(chatClient, context, selectedModel)
                        : streamingHandler.handleStreaming(chatClient, context, selectedModel);
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
                        : entityExecution.retryWhen(llmProviderRetry("LLM Entity", context)));
    }

    private <T> Mono<T> executeSecurityDecisionRawGuarded(ExecutionContext context, Class<T> targetType) {
        context.addMetadata("entityExecutionAttempted", false);
        context.addMetadata("entityExecutionSucceeded", false);
        context.addMetadata("rawExecutionAttempted", true);
        context.addMetadata("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED");
        context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
        return execute(context)
                .flatMap(rawResponse -> {
                    context.addMetadata("rawExecutionSucceeded", true);
                    context.addMetadata("structuredOutputComplete", true);
                    T parsed = targetType.cast(parseSecurityDecisionRawResponse(rawResponse, context));
                    if (!securityDecisionParsingFallbackApplied(context) || isRetryDisabled(context)) {
                        return Mono.just(parsed);
                    }
                    preserveInitialSecurityDecisionParseFailure(context);
                    resetSecurityDecisionParseFailure(context);
                    context.addMetadata("securityDecisionOutputRetryAttempted", true);
                    return execute(context).map(retryRawResponse -> {
                        T retryParsed = targetType.cast(parseSecurityDecisionRawResponse(retryRawResponse, context));
                        context.addMetadata(
                                "securityDecisionOutputRetrySucceeded",
                                !securityDecisionParsingFallbackApplied(context));
                        return retryParsed;
                    });
                })
                .onErrorResume(error -> {
                    log.error("LLM security decision raw guarded execution failed - RequestId: {}",
                            context.getRequestId(), error);
                    context.addMetadata("rawExecutionSucceeded", false);
                    String failureCategory = isTimeoutFailure(error)
                            ? providerTimeoutFailureCategory(context) : providerFailureCategory(context, error);
                    context.addMetadata("structuredOutputFailureCategory", failureCategory);
                    context.addMetadata("securityDecisionParseFailureCategory", failureCategory);
                    context.addMetadata("securityDecisionFallbackReason", "LLM_EXECUTION_FAILED");
                    context.addMetadata("securityDecisionRawExecutionFailureClass", error.getClass().getName());
                    context.addMetadata("securityDecisionRawExecutionFailureMessage", SensitiveValueSanitizer.sanitizeText(error.getMessage()));
                    context.addMetadata("structuredOutputComplete", true);
                    return Mono.just(targetType.cast(parseSecurityDecisionRawResponse("", context)));
                });
    }

    /**
     * Why a call that did not time out gave no decision: the provider stopped at the output limit (its reasoning or
     * thinking may use it up), refused, sent an empty answer, was overloaded, limited the rate (Q-38) or refused the
     * request itself; otherwise the model was unavailable.
     */
    private String providerFailureCategory(ExecutionContext context, Throwable error) {
        Object finish = context != null ? context.getMetadata().get("providerFinishReason") : null;
        String reason = finish != null ? finish.toString().trim().toLowerCase(Locale.ROOT) : "";
        if ("length".equals(reason) || "max_tokens".equals(reason)) {
            return "OUTPUT_TRUNCATED";
        }
        if ("refusal".equals(reason) || "content_filter".equals(reason)) {
            return "PROVIDER_REFUSAL";
        }
        Throwable current = error;
        while (current != null) {
            String message = current.getMessage() != null ? current.getMessage() : "";
            if (message.startsWith(EMPTY_RESPONSE_MESSAGE)) {
                return "EMPTY_RESPONSE";
            }
            Integer status = httpStatus(message);
            if ((status != null && status == PROVIDER_OVERLOADED_STATUS) || message.contains("overloaded_error")) {
                return "PROVIDER_OVERLOADED";
            }
            if (status != null && status == PROVIDER_RATE_LIMITED_STATUS) {
                return "PROVIDER_RATE_LIMITED";
            }
            if (isA(current, NON_TRANSIENT_AI_EXCEPTION)
                    && (status == null || !RETRYABLE_CLIENT_STATUSES.contains(status))) {
                return "PROVIDER_REQUEST_REJECTED";
            }
            current = current.getCause();
        }
        return "MODEL_UNAVAILABLE";
    }

    private static Integer httpStatus(String message) {
        Matcher matcher = HTTP_STATUS.matcher(message != null ? message.trim() : "");
        return matcher.find() ? Integer.valueOf(matcher.group(1)) : null;
    }

    /** Whether the throwable is of the named class or one of its subclasses. */
    private static boolean isA(Throwable throwable, String className) {
        for (Class<?> type = throwable.getClass(); type != null; type = type.getSuperclass()) {
            if (type.getName().equals(className)) {
                return true;
            }
        }
        return false;
    }

    private boolean securityDecisionParsingFallbackApplied(ExecutionContext context) {
        return context != null
                && Boolean.TRUE.equals(context.getMetadata().get("securityDecisionParsingFallbackApplied"));
    }

    private void preserveInitialSecurityDecisionParseFailure(ExecutionContext context) {
        context.addMetadata(
                "securityDecisionInitialRawOutputHash",
                context.getMetadata().get("securityDecisionRawOutputHash"));
        context.addMetadata(
                "securityDecisionInitialRawOutputLength",
                context.getMetadata().get("securityDecisionRawOutputLength"));
        context.addMetadata(
                "securityDecisionInitialParseFailureCategory",
                context.getMetadata().get("securityDecisionParseFailureCategory"));
        context.addMetadata(
                "securityDecisionInitialFallbackAction",
                context.getMetadata().get("securityDecisionFallbackAction"));
        context.addMetadata(
                "securityDecisionInitialFallbackReason",
                context.getMetadata().get("securityDecisionFallbackReason"));
    }

    private void resetSecurityDecisionParseFailure(ExecutionContext context) {
        context.addMetadata("securityDecisionParseFailureCategory", "NONE");
        context.addMetadata("structuredOutputFailureCategory", "NONE");
        context.addMetadata("securityDecisionFallbackAction", null);
        context.addMetadata("securityDecisionFallbackReason", null);
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
        long modelSelectionStart = System.currentTimeMillis();
        ChatModel selectedModel = requireSelectedModel(context);
        long modelSelectionMs = System.currentTimeMillis() - modelSelectionStart;
        recordProviderTiming(context, "providerModelSelectionMs", modelSelectionMs);
        recordChatModelClass(context, selectedModel);

        long clientBuildStart = System.currentTimeMillis();
        ChatClient chatClient = buildChatClient(selectedModel, context.getAdvisorEnabled());
        long clientBuildMs = System.currentTimeMillis() - clientBuildStart;
        recordProviderTiming(context, "providerChatClientBuildMs", clientBuildMs);

        long promptSpecStart = System.currentTimeMillis();
        ChatClient.ChatClientRequestSpec promptSpec = preparePromptSpec(chatClient, context, selectedModel);
        long promptSpecPrepareMs = System.currentTimeMillis() - promptSpecStart;
        recordProviderTiming(context, "providerPromptSpecPrepareMs", promptSpecPrepareMs);

        long providerThrottleWaitMs = throttleProviderCall(context, selectedModel);
        long providerCallStart = System.currentTimeMillis();
        ChatResponse chatResponse;
        try {
            chatResponse = executeProviderCallWithinTimeout(context, selectedModel, () -> promptSpec.call().chatResponse());
        } catch (RuntimeException ex) {
            long providerCallMs = System.currentTimeMillis() - providerCallStart;
            recordProviderFailure(context, selectedModel, providerCallMs, ex);
            throw ex;
        }
        long providerCallMs = System.currentTimeMillis() - providerCallStart;
        recordProviderTiming(context, "providerCallMs", providerCallMs);
        enforceProviderCallTimeout(context, selectedModel, providerCallMs);

        long responseMetadataStart = System.currentTimeMillis();
        captureResponseMetadata(context, selectedModel, chatResponse);
        long responseMetadataMs = System.currentTimeMillis() - responseMetadataStart;
        recordProviderTiming(context, "providerResponseMetadataMs", responseMetadataMs);
        log.info("[UnifiedLLMOrchestrator.timing] requestId={} modelClass={} modelSelectionMs={} chatClientBuildMs={} promptSpecPrepareMs={} providerThrottleWaitMs={} providerCallMs={} responseMetadataMs={}",
                context.getRequestId(),
                selectedModel.getClass().getName(),
                modelSelectionMs,
                clientBuildMs,
                promptSpecPrepareMs,
                providerThrottleWaitMs,
                providerCallMs,
                responseMetadataMs);
        return chatResponse;
    }

    private <T> ResponseEntity<ChatResponse, T> executeForResponseEntity(ExecutionContext context, Class<T> targetType) {
        long modelSelectionStart = System.currentTimeMillis();
        ChatModel selectedModel = requireSelectedModel(context);
        long modelSelectionMs = System.currentTimeMillis() - modelSelectionStart;
        recordProviderTiming(context, "providerModelSelectionMs", modelSelectionMs);
        recordChatModelClass(context, selectedModel);

        long clientBuildStart = System.currentTimeMillis();
        ChatClient chatClient = buildChatClient(selectedModel, context.getAdvisorEnabled());
        long clientBuildMs = System.currentTimeMillis() - clientBuildStart;
        recordProviderTiming(context, "providerChatClientBuildMs", clientBuildMs);

        long promptSpecStart = System.currentTimeMillis();
        ChatClient.ChatClientRequestSpec promptSpec = preparePromptSpec(chatClient, context, selectedModel);
        long promptSpecPrepareMs = System.currentTimeMillis() - promptSpecStart;
        recordProviderTiming(context, "providerPromptSpecPrepareMs", promptSpecPrepareMs);

        long providerThrottleWaitMs = throttleProviderCall(context, selectedModel);
        long providerCallStart = System.currentTimeMillis();
        ResponseEntity<ChatResponse, T> responseEntity;
        try {
            responseEntity = executeProviderCallWithinTimeout(context, selectedModel, () -> promptSpec.call().responseEntity(targetType));
        } catch (RuntimeException ex) {
            long providerCallMs = System.currentTimeMillis() - providerCallStart;
            recordProviderFailure(context, selectedModel, providerCallMs, ex);
            throw ex;
        }
        long providerCallMs = System.currentTimeMillis() - providerCallStart;
        recordProviderTiming(context, "providerCallMs", providerCallMs);
        enforceProviderCallTimeout(context, selectedModel, providerCallMs);

        long responseMetadataStart = System.currentTimeMillis();
        captureResponseMetadata(context, selectedModel, responseEntity.getResponse());
        long responseMetadataMs = System.currentTimeMillis() - responseMetadataStart;
        recordProviderTiming(context, "providerResponseMetadataMs", responseMetadataMs);
        log.info("[UnifiedLLMOrchestrator.timing] requestId={} targetType={} modelClass={} modelSelectionMs={} chatClientBuildMs={} promptSpecPrepareMs={} providerThrottleWaitMs={} providerCallMs={} responseMetadataMs={}",
                context.getRequestId(),
                targetType != null ? targetType.getName() : "unknown",
                selectedModel.getClass().getName(),
                modelSelectionMs,
                clientBuildMs,
                promptSpecPrepareMs,
                providerThrottleWaitMs,
                providerCallMs,
                responseMetadataMs);
        return responseEntity;
    }

    private <T> T executeProviderCallWithinTimeout(
            ExecutionContext context,
            ChatModel selectedModel,
            Callable<T> providerCall) {
        long timeoutMs = providerCallTimeoutMs(context);
        if (context != null && timeoutMs > 0L) {
            context.addMetadata("providerCallTimeoutMs", timeoutMs);
        }
        if (timeoutMs <= 0L) {
            return callProviderDirectly(providerCall);
        }
        Future<T> future = PROVIDER_CALL_EXECUTOR.submit(providerCall);
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException ex) {
            future.cancel(true);
            throw new ProviderCallTimeoutException(providerTimeoutMessage(selectedModel, timeoutMs), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            throw new ProviderCallTimeoutException("LLM provider call interrupted: model=" + providerModelName(selectedModel), ex);
        } catch (ExecutionException ex) {
            throw unwrapProviderExecutionException(ex);
        }
    }

    private <T> T callProviderDirectly(Callable<T> providerCall) {
        try {
            return providerCall.call();
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("LLM provider call failed", ex);
        }
    }

    private RuntimeException unwrapProviderExecutionException(ExecutionException ex) {
        Throwable cause = ex.getCause();
        if (cause instanceof RuntimeException runtimeException) {
            return runtimeException;
        }
        if (cause instanceof Error error) {
            throw error;
        }
        return new IllegalStateException("LLM provider call failed", cause);
    }

    private String providerTimeoutMessage(ChatModel selectedModel, long timeoutMs) {
        return "LLM provider call exceeded timeout before completion: " + timeoutMs + "ms, model=" + providerModelName(selectedModel);
    }

    private String providerModelName(ChatModel selectedModel) {
        return selectedModel != null ? selectedModel.getClass().getName() : "unknown";
    }

    private void recordProviderTiming(ExecutionContext context, String key, long elapsedMs) {
        if (context != null && key != null) {
            context.addMetadata(key, elapsedMs);
        }
    }

    private void recordChatModelClass(ExecutionContext context, ChatModel selectedModel) {
        if (context != null && selectedModel != null) {
            context.addMetadata("chatModelClass", selectedModel.getClass().getName());
        }
    }

    private void enforceProviderCallTimeout(ExecutionContext context, ChatModel selectedModel, long providerCallMs) {
        long timeoutMs = providerCallTimeoutMs(context);
        if (timeoutMs <= 0L) {
            return;
        }
        if (context != null) {
            context.addMetadata("providerCallTimeoutMs", timeoutMs);
        }
        if (providerCallMs <= timeoutMs) {
            return;
        }
        if (context != null) {
            context.addMetadata("providerCallExceededTimeout", true);
            context.addMetadata("providerCallFailureCategory", "PROVIDER_CALL_TIMEOUT");
            context.addMetadata("decisionFailureCategory", "PROVIDER_CALL_TIMEOUT");
            context.addMetadata("structuredOutputFailureCategory", "PROVIDER_CALL_TIMEOUT");
            context.addMetadata("securityDecisionParseFailureCategory", "PROVIDER_CALL_TIMEOUT");
        }
        String modelName = selectedModel != null ? selectedModel.getClass().getName() : "unknown";
        throw new ProviderCallTimeoutException("LLM provider call exceeded timeout: "
                + providerCallMs + "ms > " + timeoutMs + "ms, model=" + modelName);
    }

    private void recordProviderFailure(
            ExecutionContext context,
            ChatModel selectedModel,
            long providerCallMs,
            RuntimeException error) {
        recordProviderTiming(context, "providerCallMs", providerCallMs);
        if (context == null) {
            return;
        }
        String failureCategory = isTimeoutFailure(error) ? "PROVIDER_CALL_TIMEOUT" : "PROVIDER_CALL_FAILED";
        context.addMetadata("providerCallFailed", true);
        context.addMetadata("providerCallFailureCategory", failureCategory);
        context.addMetadata("providerCallFailureClass", error.getClass().getName());
        context.addMetadata("providerCallFailureMessage", SensitiveValueSanitizer.sanitizeText(error.getMessage()));
        context.addMetadata("providerCallTimeoutMs", providerCallTimeoutMs(context));
        if ("PROVIDER_CALL_TIMEOUT".equals(failureCategory)) {
            context.addMetadata("providerCallExceededTimeout", true);
            context.addMetadata("decisionFailureCategory", "PROVIDER_CALL_TIMEOUT");
            context.addMetadata("structuredOutputFailureCategory", "PROVIDER_CALL_TIMEOUT");
            context.addMetadata("securityDecisionParseFailureCategory", "PROVIDER_CALL_TIMEOUT");
        }
    }

    /** The platform's provider call limit, lowered to the calling layer's model call limit when it sets one. */
    private long providerCallTimeoutMs(ExecutionContext context) {
        long platformMs = providerCallTimeoutMs();
        long layerMs = context != null && context.getMetadata() != null
                && context.getMetadata().get(ExecutionContext.CALL_TIMEOUT_MS) instanceof Number number
                ? number.longValue()
                : 0L;
        if (layerMs <= 0L) {
            return platformMs;
        }
        return platformMs <= 0L ? layerMs : Math.min(platformMs, layerMs);
    }

    private long providerCallTimeoutMs() {
        return securityPlaneProperties != null && securityPlaneProperties.getLlmTimeout() != null
                ? Math.max(0L, securityPlaneProperties.getLlmTimeout().getProviderCallTimeoutMs())
                : 0L;
    }

    private boolean isTimeoutFailure(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof TimeoutException || current instanceof ProviderCallTimeoutException) {
                return true;
            }
            String name = current.getClass().getName();
            String message = current.getMessage();
            if ((name != null && name.toLowerCase(Locale.ROOT).contains("timeout"))
                    || (message != null && message.toLowerCase(Locale.ROOT).contains("timeout"))
                    || (message != null && message.toLowerCase(Locale.ROOT).contains("timed out"))) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private String providerTimeoutFailureCategory(ExecutionContext context) {
        if (context != null && context.getMetadata() != null) {
            Object category = context.getMetadata().get("providerCallFailureCategory");
            if (category != null && !category.toString().isBlank()) {
                return category.toString();
            }
        }
        return "PROVIDER_CALL_TIMEOUT";
    }
    private boolean isOpenAiModel(ExecutionContext context, ChatModel selectedModel) {
        if (selectedModel != null) {
            String modelClassName = selectedModel.getClass().getName().toLowerCase(Locale.ROOT);
            if (modelClassName.contains("openai")) {
                return true;
            }
        }
        if (context != null && context.getMetadata() != null) {
            Object provider = context.getMetadata().get("selectedModelProvider");
            if (provider != null && provider.toString().toLowerCase(Locale.ROOT).contains("openai")) {
                return true;
            }
            Object modelId = context.getMetadata().get("selectedModelId");
            String normalizedModelId = modelId != null ? modelId.toString().toLowerCase(Locale.ROOT) : null;
            return normalizedModelId != null
                    && (normalizedModelId.startsWith("gpt-")
                    || normalizedModelId.startsWith("o1")
                    || normalizedModelId.startsWith("o3")
                    || normalizedModelId.startsWith("o4"));
        }
        return false;
    }

    private long throttleProviderCall(ExecutionContext context, ChatModel selectedModel) {
        LlmProviderThrottleSettings settings = securityPlaneProperties != null
                ? securityPlaneProperties.getLlmProviderThrottle()
                : null;
        if (settings == null || !settings.isEnabled()) {
            if (context != null) {
                context.addMetadata("providerThrottleEnabled", false);
            }
            return 0L;
        }
        if (settings.isOpenAiOnly() && !isOpenAiModel(context, selectedModel)) {
            if (context != null) {
                context.addMetadata("providerThrottleEnabled", false);
                context.addMetadata("providerThrottleSkippedReason", "NON_OPENAI_MODEL");
            }
            return 0L;
        }
        int requestsPerMinute = Math.max(0, settings.getRequestsPerMinute());
        int tokensPerMinute = Math.max(0, settings.getTokensPerMinute());
        if (requestsPerMinute <= 0 && tokensPerMinute <= 0) {
            if (context != null) {
                context.addMetadata("providerThrottleEnabled", false);
                context.addMetadata("providerThrottleSkippedReason", "NO_LIMIT_CONFIGURED");
            }
            return 0L;
        }

        int estimatedTokens = estimateProviderThrottleTokens(context, settings);
        long start = System.currentTimeMillis();
        try {
            providerThrottle.acquire(
                    requestsPerMinute,
                    tokensPerMinute,
                    Math.max(0, settings.getMaxBurstRequests()),
                    Math.max(0, settings.getMaxBurstTokens()),
                    estimatedTokens,
                    Math.max(0L, settings.getMaxWaitMs()));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for LLM provider throttle", ex);
        }
        long waitMs = System.currentTimeMillis() - start;
        if (context != null) {
            context.addMetadata("providerThrottleEnabled", true);
            context.addMetadata("providerThrottleWaitMs", waitMs);
            context.addMetadata("providerThrottleEstimatedTokens", estimatedTokens);
            context.addMetadata("providerThrottleRequestsPerMinute", requestsPerMinute);
            context.addMetadata("providerThrottleTokensPerMinute", tokensPerMinute);
            context.addMetadata("providerThrottleMaxWaitMs", settings.getMaxWaitMs());
        }
        return waitMs;
    }

    private int estimateProviderThrottleTokens(ExecutionContext context, LlmProviderThrottleSettings settings) {
        long promptTokens = firstMetadataLong(context,
                "estimatedTotalTokens",
                "actualPromptTokens",
                "layer1ActualPromptTokens",
                "budgetEstimatedTotalTokens",
                "totalPromptEstimatedTokens",
                "userPromptEstimatedTokens");
        if (promptTokens <= 0L) {
            promptTokens = estimatePromptTextTokens(context);
        }
        long outputTokens = settings != null ? Math.max(0, settings.getEstimatedOutputTokens()) : 0L;
        long total = Math.max(1L, promptTokens + outputTokens);
        return total > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) total;
    }

    private long estimatePromptTextTokens(ExecutionContext context) {
        if (context == null || context.getPrompt() == null || context.getPrompt().getContents() == null) {
            return 1L;
        }
        return Math.max(1L, (context.getPrompt().getContents().length() + 3L) / 4L);
    }

    private long firstMetadataLong(ExecutionContext context, String... keys) {
        if (context == null || context.getMetadata() == null || keys == null) {
            return 0L;
        }
        for (String key : keys) {
            Object value = context.getMetadata().get(key);
            Long parsed = metadataLong(value);
            if (parsed != null && parsed > 0L) {
                return parsed;
            }
        }
        return 0L;
    }

    private Long metadataLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value == null) {
            return null;
        }
        try {
            return Math.round(Double.parseDouble(value.toString()));
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static final class ProviderThrottle {

        private double availableRequests;
        private double availableTokens;
        private long lastRefillNanos;
        private boolean initialized;

        synchronized void acquire(
                int requestsPerMinute,
                int tokensPerMinute,
                int maxBurstRequests,
                int maxBurstTokens,
                int estimatedTokens,
                long maxWaitMs) throws InterruptedException {
            int requiredTokens = Math.max(1, estimatedTokens);
            int requestCapacity = requestsPerMinute > 0
                    ? Math.max(1, maxBurstRequests > 0 ? maxBurstRequests : requestsPerMinute)
                    : 0;
            int tokenCapacity = tokensPerMinute > 0
                    ? Math.max(requiredTokens, maxBurstTokens > 0 ? maxBurstTokens : tokensPerMinute)
                    : 0;
            long deadlineNanos = maxWaitMs > 0L
                    ? System.nanoTime() + maxWaitMs * 1_000_000L
                    : Long.MAX_VALUE;

            while (true) {
                refill(requestsPerMinute, tokensPerMinute, requestCapacity, tokenCapacity);
                boolean requestReady = requestsPerMinute <= 0 || availableRequests >= 1.0d;
                boolean tokenReady = tokensPerMinute <= 0 || availableTokens >= requiredTokens;
                if (requestReady && tokenReady) {
                    if (requestsPerMinute > 0) {
                        availableRequests -= 1.0d;
                    }
                    if (tokensPerMinute > 0) {
                        availableTokens -= requiredTokens;
                    }
                    return;
                }

                long waitNanos = waitNanos(
                        requestsPerMinute,
                        tokensPerMinute,
                        requiredTokens,
                        requestReady,
                        tokenReady);
                long now = System.nanoTime();
                if (now + waitNanos > deadlineNanos) {
                    throw new IllegalStateException("LLM provider throttle wait exceeded");
                }
                long waitMs = Math.max(1L, Math.min(250L, waitNanos / 1_000_000L));
                wait(waitMs);
            }
        }

        private void refill(int requestsPerMinute, int tokensPerMinute, int requestCapacity, int tokenCapacity) {
            long now = System.nanoTime();
            if (!initialized) {
                initialized = true;
                lastRefillNanos = now;
                availableRequests = requestCapacity;
                availableTokens = tokenCapacity;
                return;
            }
            double elapsedMinutes = (now - lastRefillNanos) / 60_000_000_000.0d;
            if (elapsedMinutes <= 0.0d) {
                return;
            }
            lastRefillNanos = now;
            if (requestsPerMinute > 0) {
                availableRequests = Math.min(requestCapacity, availableRequests + elapsedMinutes * requestsPerMinute);
            }
            if (tokensPerMinute > 0) {
                availableTokens = Math.min(tokenCapacity, availableTokens + elapsedMinutes * tokensPerMinute);
            }
        }

        private long waitNanos(
                int requestsPerMinute,
                int tokensPerMinute,
                int requiredTokens,
                boolean requestReady,
                boolean tokenReady) {
            double waitMinutes = 0.0d;
            if (!requestReady && requestsPerMinute > 0) {
                waitMinutes = Math.max(waitMinutes, (1.0d - availableRequests) / requestsPerMinute);
            }
            if (!tokenReady && tokensPerMinute > 0) {
                waitMinutes = Math.max(waitMinutes, (requiredTokens - availableTokens) / tokensPerMinute);
            }
            return Math.max(1_000_000L, Math.round(waitMinutes * 60_000_000_000.0d));
        }
    }
    private static final class ProviderCallTimeoutException extends RuntimeException {
        private ProviderCallTimeoutException(String message) {
            super(message);
        }

        private ProviderCallTimeoutException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private ChatModel requireSelectedModel(ExecutionContext context) {
        ChatModel selectedModel = modelSelectionStrategy.selectModel(context);
        if (selectedModel == null) {
            throw new IllegalStateException(
                    "No LLM model configured. " +
                            "Add at least one Spring AI chat provider starter to the application dependencies, configure the matching provider under spring.ai.*, and ensure a ChatModel bean is available to CONTEXA.");
        }
        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(selectedModel);
        return selectedModel;
    }

    private ChatClient.ChatClientRequestSpec preparePromptSpec(ChatClient chatClient,
                                                               ExecutionContext context,
                                                               ChatModel selectedModel) {
        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(selectedModel);
        Prompt prompt = ProviderAwareChatOptionsFactory.normalizePromptOptions(context.getPrompt(), context, selectedModel);
        ChatClient.ChatClientRequestSpec promptSpec = chatClient.prompt(prompt);
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
        if (advisorEnabled && context.getMetadata() != null
                && context.getMetadata().get(LlmObservationContext.CONTEXT_KEY)
                        instanceof LlmObservationContext observation) {
            promptSpec = promptSpec.advisors(spec -> spec.param(LlmObservationContext.CONTEXT_KEY, observation));
        }
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

    /**
     * The answer text. A provider that returns its thinking as generations before the answer (Anthropic's thinking
     * blocks, which carry their signature, and redacted ones, which carry their data) has its answer in the other
     * generations, and with thinking alone (the output limit stopped it before the answer) no answer came back.
     */
    private String extractResponseText(ChatResponse chatResponse) {
        if (chatResponse == null || chatResponse.getResult() == null || chatResponse.getResult().getOutput() == null) {
            return null;
        }
        StringBuilder answer = new StringBuilder();
        boolean answered = false;
        boolean thought = false;
        for (Generation generation : chatResponse.getResults()) {
            AssistantMessage output = generation != null ? generation.getOutput() : null;
            if (output == null) {
                continue;
            }
            if (isThinking(output)) {
                thought = true;
                continue;
            }
            answered = true;
            if (output.getText() != null) {
                answer.append(output.getText());
            }
        }
        if (!thought) {
            return chatResponse.getResult().getOutput().getText();
        }
        return answered ? answer.toString() : null;
    }

    private static boolean isThinking(AssistantMessage output) {
        return ThinkingGenerationAdvisor.isThinking(output);
    }

    private void captureResponseMetadata(ExecutionContext context, ChatModel selectedModel, ChatResponse chatResponse) {
        if (context == null) {
            return;
        }
        if (chatResponse == null) {
            context.addMetadata("actualTokenUsageAvailable", false);
            return;
        }

        // The finish reason of the answer: a cut at the output limit or a refusal is told apart when no decision came.
        String finishReason = answerFinishReason(chatResponse);
        if (finishReason != null) {
            context.addMetadata("providerFinishReason", finishReason);
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
        // Every input token, as OpenAI counts them (Anthropic counts its prompt cache reads and writes apart).
        Integer promptTokens = ProviderUsage.promptTokens(usage);
        Integer completionTokens = usage != null ? usage.getCompletionTokens() : null;
        Integer totalTokens = ProviderUsage.totalTokens(usage);
        Integer cacheWrites = ProviderUsage.cacheWriteTokens(usage);
        if (cacheWrites != null) {
            context.addMetadata("cacheWritePromptTokens", cacheWrites);
        }
        Integer reasoningTokens = ProviderUsage.reasoningTokens(usage);
        if (reasoningTokens != null) {
            context.addMetadata("reasoningTokens", reasoningTokens);
        }
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

        // A provider that reports no cached token count leaves the hit unknown, so no hit value is recorded.
        Integer cachedPromptTokens = extractCachedPromptTokens(metadata, usage);
        if (cachedPromptTokens != null) {
            context.addMetadata("cachedPromptTokens", cachedPromptTokens);
            context.addMetadata("promptCacheHit", cachedPromptTokens > 0);
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
            String key = entry.getKey() != null ? entry.getKey().toLowerCase(Locale.ROOT) : "";
            if (entry.getValue() instanceof Number number) {
                // A number under another name (a creation time, an evaluation count) is no cached token count.
                if (key.contains("cached")) {
                    return number.intValue();
                }
                continue;
            }
            Integer extracted = extractCachedPromptTokensFromUnknown(entry.getValue());
            if (extracted != null) {
                return extracted;
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
        for (String methodName : List.of("cachedTokens", "getCachedTokens", "cacheReadInputTokens")) {
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

    /** The finish reason of the answer generation (a thinking generation comes first), else of the first one. */
    private static String answerFinishReason(ChatResponse chatResponse) {
        String first = null;
        for (Generation generation : chatResponse.getResults()) {
            if (generation == null || generation.getMetadata() == null) {
                continue;
            }
            String reason = generation.getMetadata().getFinishReason();
            if (reason == null || reason.isBlank()) {
                continue;
            }
            if (first == null) {
                first = reason;
            }
            if (generation.getOutput() != null && !isThinking(generation.getOutput())) {
                return reason;
            }
        }
        return first;
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
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolProviders(toolProviders)
                .toolExecutionEnabled(true)
                .build();
        return executeChatResponse(context);
    }

    @Override
    public Mono<ChatResponse> callToolCallbacksResponse(Prompt prompt, ToolCallback[] toolCallbacks) {
        ExecutionContext context = ExecutionContext.builder()
                .prompt(prompt)
                .toolCallbacks(List.of(toolCallbacks))
                .toolExecutionEnabled(true)
                .build();
        return executeChatResponse(context);
    }

    /**
     * The whole response of a call, on the same path as execute: the model selection, the options and the tools, the
     * provider time limit, the response metadata, and the retry of a failure that may pass when sent again.
     */
    private Mono<ChatResponse> executeChatResponse(ExecutionContext context) {
        Mono<ChatResponse> execution = Mono.fromCallable(() -> executeForChatResponse(context))
                .doOnError(error -> log.error("LLM tool call failed - RequestId: {}", context.getRequestId(), error));
        return isRetryDisabled(context) ? execution : execution.retryWhen(llmProviderRetry("LLM tool call", context));
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

    /** The observation registry the ChatClients observe through (Spring AI's chat client and advisor observations). */
    public void setObservationRegistry(ObservationRegistry observationRegistry) {
        this.observationRegistry = observationRegistry != null ? observationRegistry : ObservationRegistry.NOOP;
        chatClientCache.clear();
        chatClientNoAdvisorCache.clear();
    }

    private ChatClient buildChatClient(ChatModel model, Boolean advisorEnabled) {
        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(model);
        if (!isAdvisorEnabled(advisorEnabled)) {
            return chatClientNoAdvisorCache.computeIfAbsent(model,
                    m -> chatClientBuilder(m).defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE).build());
        }

        List<Advisor> currentAdvisors = advisorRegistry.getEnabled();

        if (!currentAdvisors.equals(cachedAdvisorSnapshot)) {
            chatClientCache.clear();
            cachedAdvisorSnapshot = List.copyOf(currentAdvisors);
        }

        return chatClientCache.computeIfAbsent(model, m -> {
            ChatClient.Builder builder = chatClientBuilder(m).defaultAdvisors(ThinkingGenerationAdvisor.INSTANCE);
            if (!currentAdvisors.isEmpty()) {
                builder = builder.defaultAdvisors(currentAdvisors.toArray(new Advisor[0]));
            }
            return builder.build();
        });
    }

    private ChatClient.Builder chatClientBuilder(ChatModel model) {
        return ChatClient.builder(model, observationRegistry, null, null);
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

    private Retry llmProviderRetry(String operation, ExecutionContext context) {
        return Retry.backoff(4, Duration.ofSeconds(2))
                .maxBackoff(Duration.ofSeconds(12))
                .filter(this::isRetryableProviderFailure)
                .doBeforeRetry(retrySignal -> {
                    long retryCount = retrySignal.totalRetries() + 1;
                    if (context != null) {
                        context.addMetadata("providerRetryCount", retryCount);
                    }
                    log.warn("{} Retry #{} - RequestId: {}, Error: {}",
                            operation,
                            retryCount,
                            context != null ? context.getRequestId() : "unknown",
                            retrySignal.failure() != null ? retrySignal.failure().getMessage() : "unknown");
                });
    }

    private boolean isRetryableProviderFailure(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (isA(current, NON_TRANSIENT_AI_EXCEPTION)) {
                // The provider refused the request itself (an HTTP 4xx): sent again it gets the same answer, unless
                // the status is a timeout, a conflict or a rate limit.
                Integer status = httpStatus(current.getMessage());
                return status != null && RETRYABLE_CLIENT_STATUSES.contains(status);
            }
            if (isA(current, TRANSIENT_AI_EXCEPTION) || current instanceof IOException) {
                return true;
            }
            String className = current.getClass().getName();
            String message = current.getMessage();
            String normalized = message != null ? message.toLowerCase(Locale.ROOT) : "";
            if (normalized.contains("http 429")
                    || normalized.contains("http 408")
                    || normalized.contains("http 502")
                    || normalized.contains("http 503")
                    || normalized.contains("http 504")
                    || normalized.contains("bad gateway")
                    || normalized.contains("service unavailable")
                    || normalized.contains("gateway timeout")
                    || normalized.contains("upstream connect")
                    || normalized.contains("disconnect/reset")
                    || normalized.contains("connection termination")
                    || normalized.contains("connection reset")
                    || normalized.contains("connection refused")
                    || normalized.contains("temporarily unavailable")
                    || normalized.contains("429 too many requests")
                    || normalized.contains("rate limit")
                    || normalized.contains("rate_limit_exceeded")
                    || normalized.contains("requests per min")
                    || normalized.contains("tokens per min")
                    || normalized.contains("try again in")
                    || (className != null && className.toLowerCase(Locale.ROOT).contains("ratelimit"))) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }}

