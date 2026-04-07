package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
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
            "decisionBoundaryMode"
    );

    private final LLMClient llmClient;

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

        if (finalTargetType != null && !preferRawExecution(finalTargetType)) {
            return preparePrompt(context)
                    .flatMap(prompt -> executeEntity(prompt, request, context, finalTargetType)
                            .doOnSuccess(response -> {
                                context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                                context.addMetadata("structuredOutputComplete", true);
                            })
                            .cast(Object.class)
                            .onErrorResume(error -> {
                                log.error("[PIPELINE-STEP] Structured output execution failed. Attempting raw String fallback. Request: {}", request.getRequestId(), error);
                                context.addMetadata("structuredOutputComplete", false);
                                return executeRaw(prompt, request, context)
                                        .switchIfEmpty(Mono.error(new IllegalStateException("LLM raw fallback returned empty Mono")))
                                        .doOnSuccess(rawResponse -> context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, rawResponse))
                                        .cast(Object.class);
                            }))
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .onErrorResume(Mono::error);
        }

        return preparePrompt(context)
                .flatMap(prompt -> {
                    context.addMetadata("structuredOutputComplete", false);
                    return executeRaw(prompt, request, context);
                })
                .doOnSuccess(response -> context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response))
                .cast(Object.class)
                .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
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

    private boolean preferRawExecution(Class<?> targetType) {
        return SecurityDecisionResponse.class.equals(targetType)
                || SecurityDecisionResponseLite.class.equals(targetType);
    }

    private <T extends DomainContext> Mono<?> executeEntity(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context,
            Class<?> targetType) {
        ExecutionContext executionContext = buildExecutionContext(prompt, request, context);
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
        ExecutionContext executionContext = buildExecutionContext(prompt, request, context);
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
        ExecutionContext executionContext = buildExecutionContext(prompt, request, context);
        if (llmClient instanceof LLMOperations operations) {
            return operations.stream(executionContext)
                    .doOnNext(chunk -> syncExecutionMetadata(context, executionContext));
        }
        return llmClient.stream(prompt);
    }

    private <T extends DomainContext> ExecutionContext buildExecutionContext(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
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
        return executionContext;
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
