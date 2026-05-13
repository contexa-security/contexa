package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.ObservedPromptTokenUsageRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapability;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.client.advisor.StructuredOutputValidationAdvisor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
public class LLMExecutionStep implements PipelineStep {

    private static final List<String> EXECUTION_METADATA_KEYS = List.of(
            "requestedModelId",
            "requestedModelSourceKey",
            "preferredModel",
            "selectedModelId",
            "selectedModelProvider",
            "runtimeModelId",
            "modelSelectionSource",
            "modelSelectionFallbackUsed",
            "modelSelectionFailure",
            "modelSelectionCandidates",
            "temperature",
            "topP",
            "seed",
            "maxTokens",
            "disableRetries",
            "disableOllamaThinking",
            "decisionBoundaryMode",
            "structuredOutputMode",
            "structuredOutputPolicy",
            "structuredOutputValidationMaxAttempts",
            "providerResponseId",
            "providerResponseModel",
            "actualPromptTokens",
            "actualCompletionTokens",
            "actualTotalTokens",
            "actualTokenUsageAvailable",
            "promptCacheHit",
            "cachedPromptTokens"
    );

    private final LLMClient llmClient;
    private final StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry;

    public LLMExecutionStep(LLMClient llmClient) {
        this(llmClient, StructuredOutputCapabilityRegistry.defaultRegistry());
    }

    public LLMExecutionStep(LLMClient llmClient, StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        this.llmClient = llmClient;
        this.structuredOutputCapabilityRegistry = structuredOutputCapabilityRegistry != null
                ? structuredOutputCapabilityRegistry
                : StructuredOutputCapabilityRegistry.defaultRegistry();
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        long stepStartTime = System.currentTimeMillis();

        Class<?> targetType = context.getMetadata("aiGenerationType", Class.class);
        if (targetType == null) {
            targetType = context.getMetadata("targetResponseType", Class.class);
        }
        if (targetType == null) {
            targetType = request.getParameter("responseType", Class.class);
        }

        final Class<?> finalTargetType = targetType;
        final StructuredOutputCapability capability = resolveStructuredOutputCapability(request, context, finalTargetType);
        final StructuredOutputMode structuredOutputMode = resolveStructuredOutputMode(request, context, finalTargetType, capability);
        final StructuredOutputPolicy structuredOutputPolicy = resolveStructuredOutputPolicy(request, context, finalTargetType);
        context.addMetadata("structuredOutputProviderFamily", capability.providerFamily());
        context.addMetadata("structuredOutputNativeSupported", capability.nativeStructuredSupported());
        context.addMetadata("structuredOutputValidationAdvisorSupported", capability.validationAdvisorSupported());
        context.addMetadata("structuredOutputCapabilitySource", capability.resolutionSource());

        if (isSecurityDecisionTarget(finalTargetType)) {
            context.addMetadata("entityExecutionAttempted", false);
            context.addMetadata("entityExecutionSucceeded", false);
            context.addMetadata("rawExecutionAttempted", true);
            context.addMetadata("structuredOutputComplete", false);
            context.addMetadata("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED");
            context.addMetadata("structuredOutputPolicy", structuredOutputPolicy.name());
            context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
            return preparePrompt(context)
                    .flatMap(prompt -> executeRaw(prompt, request, context)
                            .switchIfEmpty(Mono.error(new IllegalStateException("Security decision LLM raw execution returned empty Mono")))
                            .doOnSuccess(rawResponse -> {
                                context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, rawResponse);
                                context.addMetadata("rawExecutionSucceeded", true);
                                context.addMetadata("structuredOutputMode", "SECURITY_DECISION_RAW_GUARDED");
                                context.addMetadata("structuredOutputPolicy", structuredOutputPolicy.name());
                                context.addMetadata("securityDecisionParsingMode", "RAW_GUARDED");
                            }))
                    .cast(Object.class)
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .doFinally(signalType -> context.addMetadata("llmExecutionLatencyMs", System.currentTimeMillis() - stepStartTime))
                    .onErrorResume(error -> {
                        log.error("[PIPELINE-STEP] Security decision raw execution failed; fail-closed parsing will produce a challenge. Request: {}",
                                request.getRequestId(), error);
                        context.addMetadata("rawExecutionSucceeded", false);
                        context.addMetadata("structuredOutputFailureCategory", "MODEL_UNAVAILABLE");
                        context.addMetadata("securityDecisionParseFailureCategory", "MODEL_UNAVAILABLE");
                        context.addMetadata("securityDecisionFallbackReason", "LLM_EXECUTION_FAILED");
                        context.addMetadata("securityDecisionRawExecutionFailureClass", error.getClass().getName());
                        context.addMetadata("securityDecisionRawExecutionFailureMessage", error.getMessage());
                        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, "");
                        return Mono.just("");
                    });
        }

        if (finalTargetType != null && structuredOutputMode != StructuredOutputMode.LEGACY_RAW) {
            context.addMetadata("entityExecutionAttempted", true);
            context.addMetadata("rawExecutionAttempted", false);
            context.addMetadata("structuredOutputMode", structuredOutputMode.name());
            context.addMetadata("structuredOutputPolicy", structuredOutputPolicy.name());
            return preparePrompt(context)
                    .flatMap(prompt -> executeEntity(prompt, request, context, finalTargetType, structuredOutputMode, structuredOutputPolicy)
                            .doOnSuccess(response -> {
                                context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                                context.addMetadata("structuredOutputComplete", true);
                                context.addMetadata("entityExecutionSucceeded", true);
                            })
                            .cast(Object.class)
                            .onErrorResume(error -> {
                                context.addMetadata("entityExecutionSucceeded", false);
                                context.addMetadata("structuredOutputComplete", false);
                                context.addMetadata("structuredOutputFailureCategory", categorizeFailure(error).name());
                                if (!structuredOutputPolicy.allowsRawFallback()) {
                                    log.error("[PIPELINE-STEP] Structured output execution failed and raw fallback is forbidden. Request: {}",
                                            request.getRequestId(), error);
                                    return Mono.error(asStructuredOutputExecutionException(error));
                                }
                                log.error("[PIPELINE-STEP] Structured output execution failed. Attempting raw String fallback. Request: {}", request.getRequestId(), error);
                                context.addMetadata("rawExecutionAttempted", true);
                                context.addMetadata("structuredOutputMode", StructuredOutputMode.LEGACY_RAW.name());
                                return executeRaw(prompt, request, context)
                                        .switchIfEmpty(Mono.error(new IllegalStateException("LLM raw fallback returned empty Mono")))
                                        .doOnSuccess(rawResponse -> context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, rawResponse))
                                        .cast(Object.class);
                            }))
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .doFinally(signalType -> context.addMetadata("llmExecutionLatencyMs", System.currentTimeMillis() - stepStartTime))
                    .onErrorResume(Mono::error);
        }

        return preparePrompt(context)
                .flatMap(prompt -> {
                    context.addMetadata("entityExecutionAttempted", false);
                    context.addMetadata("structuredOutputComplete", false);
                    context.addMetadata("rawExecutionAttempted", true);
                    context.addMetadata("structuredOutputMode", StructuredOutputMode.LEGACY_RAW.name());
                    return executeRaw(prompt, request, context);
                })
                .doOnSuccess(response -> context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response))
                .cast(Object.class)
                .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                .doFinally(signalType -> context.addMetadata("llmExecutionLatencyMs", System.currentTimeMillis() - stepStartTime))
                .onErrorResume(error -> {
                    log.error("[PIPELINE-STEP] LLM execution failed. Request: {}", request.getRequestId());
                    return Mono.error(error);
                });
    }

    public <T extends DomainContext> Flux<String> executeStreaming(AIRequest<T> request, PipelineExecutionContext context) {
        return preparePrompt(context)
                .flatMapMany(prompt -> executeStream(prompt, request, context))
                .doOnError(error -> log.error("[PIPELINE-STEP] Streaming execution failed. Request: {}", request.getRequestId(), error));
    }

    protected Mono<Prompt> preparePrompt(PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            PromptGenerationResult promptResult = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PROMPT_GENERATION, PromptGenerationResult.class);

            if (promptResult == null || promptResult.getPrompt() == null) {
                throw new IllegalStateException("Prompt not found in context. Skipping LLM execution.");
            }
            return promptResult.getPrompt();
        }).onErrorResume(IllegalStateException.class, e -> {
            log.error("[PIPELINE-STEP] {}", e.getMessage());
            return Mono.error(e);
        });
    }

    private <T extends DomainContext> Mono<?> executeEntity(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType,
            StructuredOutputMode structuredOutputMode,
            StructuredOutputPolicy structuredOutputPolicy) {
        ExecutionContext executionContext = buildExecutionContext(prompt, request, context, targetType, structuredOutputMode, structuredOutputPolicy);
        if (llmClient instanceof LLMOperations operations) {
            return operations.executeEntity(executionContext, targetType)
                    .doOnSuccess(response -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.entity(prompt, targetType);
    }

    private <T extends DomainContext> Mono<String> executeRaw(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        ExecutionContext executionContext = buildExecutionContext(
                prompt,
                request,
                context,
                null,
                StructuredOutputMode.LEGACY_RAW,
                StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        if (llmClient instanceof LLMOperations operations) {
            return operations.execute(executionContext)
                    .doOnSuccess(response -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.call(prompt);
    }

    private <T extends DomainContext> Flux<String> executeStream(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        ExecutionContext executionContext = buildExecutionContext(
                prompt,
                request,
                context,
                null,
                StructuredOutputMode.LEGACY_RAW,
                StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        if (llmClient instanceof LLMOperations operations) {
            return operations.stream(executionContext)
                    .doOnNext(chunk -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.stream(prompt);
    }

    private <T extends DomainContext> ExecutionContext buildExecutionContext(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType,
            StructuredOutputMode structuredOutputMode,
            StructuredOutputPolicy structuredOutputPolicy) {
        ExecutionContext executionContext = ExecutionContext.from(prompt);
        executionContext.setRequestId(request != null ? request.getRequestId() : null);

        ResolvedValue<String> requestedModel = resolveStringParameter(request, context,
                "preferredModel",
                "requestedModelId",
                "runtimeModelId");
        ResolvedValue<Double> temperature = resolveDoubleParameter(request, context,
                "temperature",
                "runtimeTemperature");
        ResolvedValue<Double> topP = resolveDoubleParameter(request, context,
                "topP",
                "runtimeTopP");
        ResolvedValue<Integer> seed = resolveIntegerParameter(request, context,
                "seed",
                "runtimeSeed");
        ResolvedValue<Integer> maxTokens = resolveIntegerParameter(request, context,
                "maxTokens",
                "runtimeMaxTokens");
        ResolvedValue<Boolean> disableRetries = resolveBooleanParameter(request, context, "disableRetries");
        ResolvedValue<Boolean> disableOllamaThinking = resolveBooleanParameter(request, context, "disableOllamaThinking");
        ResolvedValue<String> boundaryMode = resolveStringParameter(request, context, "decisionBoundaryMode");

        if (boundaryMode == null && hasAnyRuntimeOverrides(requestedModel, temperature, topP, seed, maxTokens, disableRetries, disableOllamaThinking)) {
            boundaryMode = new ResolvedValue<>("RUNTIME_MODEL_SELECTION", "derived.runtimeSelection");
        }

        if (requestedModel != null) {
            executionContext.setPreferredModel(requestedModel.value());
            recordMetadata(context, executionContext, "requestedModelId", requestedModel.value());
            recordMetadata(context, executionContext, "preferredModel", requestedModel.value());
            recordMetadata(context, executionContext, "runtimeModelId", requestedModel.value());
            recordMetadata(context, executionContext, "requestedModelSourceKey", requestedModel.sourceKey());
        }
        if (temperature != null) {
            executionContext.setTemperature(temperature.value());
            recordMetadata(context, executionContext, "temperature", temperature.value());
        }
        if (topP != null) {
            executionContext.setTopP(topP.value());
            recordMetadata(context, executionContext, "topP", topP.value());
        }
        if (seed != null) {
            executionContext.setSeed(seed.value());
            recordMetadata(context, executionContext, "seed", seed.value());
        }
        if (maxTokens != null) {
            executionContext.setMaxTokens(maxTokens.value());
            recordMetadata(context, executionContext, "maxTokens", maxTokens.value());
        }
        if (disableRetries != null) {
            executionContext.addMetadata("disableRetries", disableRetries.value());
            recordMetadata(context, executionContext, "disableRetries", disableRetries.value());
        }
        if (disableOllamaThinking != null) {
            executionContext.addMetadata("disableOllamaThinking", disableOllamaThinking.value());
            recordMetadata(context, executionContext, "disableOllamaThinking", disableOllamaThinking.value());
        }
        if (boundaryMode != null) {
            recordMetadata(context, executionContext, "decisionBoundaryMode", boundaryMode.value());
        }
        if (structuredOutputMode != null) {
            recordMetadata(context, executionContext, "structuredOutputMode", structuredOutputMode.name());
        }
        if (structuredOutputPolicy != null) {
            recordMetadata(context, executionContext, "structuredOutputPolicy", structuredOutputPolicy.name());
        }
        recordMetadata(context, executionContext, "structuredOutputProviderFamily",
                context != null ? context.getMetadata("structuredOutputProviderFamily", Object.class) : null);
        recordMetadata(context, executionContext, "structuredOutputNativeSupported",
                context != null ? context.getMetadata("structuredOutputNativeSupported", Object.class) : null);
        recordMetadata(context, executionContext, "structuredOutputValidationAdvisorSupported",
                context != null ? context.getMetadata("structuredOutputValidationAdvisorSupported", Object.class) : null);
        recordMetadata(context, executionContext, "structuredOutputCapabilitySource",
                context != null ? context.getMetadata("structuredOutputCapabilitySource", Object.class) : null);
        if (targetType != null && structuredOutputMode != StructuredOutputMode.LEGACY_RAW) {
            ResolvedValue<Integer> validationAttempts = resolveIntegerParameter(request, context, "structuredOutputValidationMaxAttempts");
            int maxRepeatAttempts = validationAttempts != null
                    ? Math.max(0, validationAttempts.value())
                    : 1;
            if (structuredOutputMode == StructuredOutputMode.VALIDATED_CONVERTER) {
                executionContext.addAdvisor(StructuredOutputValidationAdvisor.builder()
                        .outputType(targetType)
                        .maxRepeatAttempts(maxRepeatAttempts)
                        .build());
            }
            recordMetadata(context, executionContext, "structuredOutputValidationMaxAttempts", maxRepeatAttempts);
        }
        return executionContext;
    }

    private <T extends DomainContext> StructuredOutputMode resolveStructuredOutputMode(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType,
            StructuredOutputCapability capability) {
        if (targetType == null) {
            return StructuredOutputMode.LEGACY_RAW;
        }
        Object configuredMode = resolveRawParameter(request, context, "structuredOutputMode");
        if (configuredMode != null) {
            StructuredOutputMode resolved = StructuredOutputMode.fromValue(configuredMode, StructuredOutputMode.VALIDATED_CONVERTER);
            return resolved;
        }
        ResolvedValue<Boolean> nativeStructuredEnabled = resolveBooleanParameter(request, context, "nativeStructuredOutputEnabled");
        if (nativeStructuredEnabled != null
                && !nativeStructuredEnabled.value()
                && capability.nativeStructuredSupported()) {
            return StructuredOutputMode.VALIDATED_CONVERTER;
        }
        return capability.resolvePreferredMode();
    }

    private <T extends DomainContext> StructuredOutputCapability resolveStructuredOutputCapability(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType) {
        String modelHint = null;
        ResolvedValue<String> requestedModel = resolveStringParameter(request, context,
                "requestedModelId",
                "preferredModel",
                "runtimeModelId",
                "officialVerificationPinnedModelId");
        if (requestedModel != null) {
            modelHint = requestedModel.value();
        }
        String providerHint = null;
        ResolvedValue<String> providerValue = resolveStringParameter(request, context,
                "selectedModelProvider",
                "providerResponseModel");
        if (providerValue != null) {
            providerHint = providerValue.value();
        }
        return structuredOutputCapabilityRegistry.resolve(modelHint, providerHint, targetType != null);
    }

    private boolean isSecurityDecisionTarget(Class<?> targetType) {
        return SecurityDecisionResponseLite.class.equals(targetType);
    }

    private <T extends DomainContext> StructuredOutputPolicy resolveStructuredOutputPolicy(
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType) {
        Object configuredPolicy = resolveRawParameter(request, context, "structuredOutputPolicy");
        if (configuredPolicy != null) {
            return StructuredOutputPolicy.fromValue(configuredPolicy, StructuredOutputPolicy.ALLOW_RAW_FALLBACK);
        }
        return targetType != null
                ? StructuredOutputPolicy.ALLOW_RAW_FALLBACK
                : StructuredOutputPolicy.ALLOW_RAW_FALLBACK;
    }

    private StructuredOutputFailureCategory categorizeFailure(Throwable error) {
        if (error instanceof StructuredOutputExecutionException structuredException) {
            return structuredException.getCategory();
        }
        return StructuredOutputFailureCategory.ENTITY_EXECUTION_FAILED;
    }

    private StructuredOutputExecutionException asStructuredOutputExecutionException(Throwable error) {
        if (error instanceof StructuredOutputExecutionException structuredException) {
            return structuredException;
        }
        return new StructuredOutputExecutionException(
                StructuredOutputFailureCategory.ENTITY_EXECUTION_FAILED,
                "Structured output execution failed",
                error);
    }

    private boolean hasAnyRuntimeOverrides(Object... values) {
        for (Object value : values) {
            if (value != null) {
                return true;
            }
        }
        return false;
    }

    private void syncExecutionMetadata(PipelineExecutionContext context, ExecutionContext executionContext) {
        if (context == null || executionContext == null || executionContext.getMetadata() == null) {
            return;
        }
        for (String key : EXECUTION_METADATA_KEYS) {
            Object value = executionContext.getMetadata().get(key);
            if (value != null) {
                context.addMetadata(key, value);
            }
        }
        reconcileActualPromptBudgetTelemetry(context);
        recordObservedPromptTokenUsage(context);
    }

    private void reconcileActualPromptBudgetTelemetry(PipelineExecutionContext context) {
        Number actualPromptTokens = context.getMetadata("actualPromptTokens", Number.class);
        Number budgetMaxInputTokens = context.getMetadata("budgetMaxInputTokens", Number.class);
        Boolean usageAvailable = context.getMetadata("actualTokenUsageAvailable", Boolean.class);
        if (actualPromptTokens == null || budgetMaxInputTokens == null || !Boolean.TRUE.equals(usageAvailable)) {
            return;
        }
        int actualInput = Math.max(0, actualPromptTokens.intValue());
        int maxInput = Math.max(1, budgetMaxInputTokens.intValue());
        int remaining = maxInput - actualInput;
        double utilizationRate = actualInput / (double) maxInput;
        context.addMetadata("actualPromptBudgetRemainingTokens", remaining);
        context.addMetadata("actualPromptBudgetUtilizationRate", utilizationRate);
        context.addMetadata("actualPromptBudgetExceeded", actualInput > maxInput);
        context.addMetadata("actualPromptUsageSource", "PROVIDER_USAGE");
    }

    private void recordObservedPromptTokenUsage(PipelineExecutionContext context) {
        Number actualPromptTokens = context.getMetadata("actualPromptTokens", Number.class);
        Boolean usageAvailable = context.getMetadata("actualTokenUsageAvailable", Boolean.class);
        if (actualPromptTokens == null || !Boolean.TRUE.equals(usageAvailable)) {
            return;
        }
        Number promptLength = context.getMetadata("llmTotalPromptLength", Number.class);
        if (promptLength == null) {
            promptLength = context.getMetadata("totalPromptLength", Number.class);
        }
        if (promptLength == null || promptLength.intValue() <= 0) {
            return;
        }
        for (String modelHint : new String[] {
                context.getMetadata("requestedModelId", String.class),
                context.getMetadata("preferredModel", String.class),
                context.getMetadata("runtimeModelId", String.class),
                context.getMetadata("selectedModelId", String.class),
                context.getMetadata("providerResponseModel", String.class)}) {
            ObservedPromptTokenUsageRegistry.recordObservation(
                    modelHint,
                    promptLength.intValue(),
                    actualPromptTokens.intValue());
        }
    }

    private void recordMetadata(
            PipelineExecutionContext context,
            ExecutionContext executionContext,
            String key,
            Object value) {
        if (context != null && key != null && value != null) {
            context.addMetadata(key, value);
        }
        if (executionContext != null && key != null && value != null) {
            executionContext.addMetadata(key, value);
        }
    }

    private <T extends DomainContext> Object resolveRawParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String key) {
        if (request != null && request.getParameters().containsKey(key)) {
            return request.getParameters().get(key);
        }
        return context != null ? context.getMetadata(key, Object.class) : null;
    }

    private <T extends DomainContext> ResolvedValue<String> resolveStringParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof String text && !text.isBlank()) {
                return new ResolvedValue<>(text.trim(), key);
            }
            if (value != null) {
                String text = String.valueOf(value).trim();
                if (!text.isEmpty()) {
                    return new ResolvedValue<>(text, key);
                }
            }
        }
        return null;
    }

    private <T extends DomainContext> ResolvedValue<Double> resolveDoubleParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof Double number) {
                return new ResolvedValue<>(number, key);
            }
            if (value instanceof Number number) {
                return new ResolvedValue<>(number.doubleValue(), key);
            }
            if (value instanceof String text && !text.isBlank()) {
                try {
                    return new ResolvedValue<>(Double.parseDouble(text.trim()), key);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private <T extends DomainContext> ResolvedValue<Integer> resolveIntegerParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof Integer number) {
                return new ResolvedValue<>(number, key);
            }
            if (value instanceof Number number) {
                return new ResolvedValue<>(number.intValue(), key);
            }
            if (value instanceof String text && !text.isBlank()) {
                try {
                    return new ResolvedValue<>(Integer.parseInt(text.trim()), key);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private <T extends DomainContext> ResolvedValue<Boolean> resolveBooleanParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String... keys) {
        for (String key : keys) {
            Object value = resolveRawParameter(request, context, key);
            if (value instanceof Boolean bool) {
                return new ResolvedValue<>(bool, key);
            }
            if (value instanceof String text && !text.isBlank()) {
                return new ResolvedValue<>(Boolean.parseBoolean(text.trim()), key);
            }
        }
        return null;
    }

    private void logError(String requestId, Throwable error, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.error("[PIPELINE-STEP] LLM execution failed - Request: {}, Duration: {}ms, Error: {}",
                requestId, totalTime, error.getMessage());
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.LLM_EXECUTION;
    }

    public LLMClient getLlmClient() {
        return llmClient;
    }

    @Override
    public int getOrder() {
        return 4;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return llmClient != null;
    }

    private record ResolvedValue<T>(T value, String sourceKey) {
    }
}
