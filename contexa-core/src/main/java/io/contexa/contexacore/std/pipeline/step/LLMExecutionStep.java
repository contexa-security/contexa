package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class LLMExecutionStep implements PipelineStep {

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
        if (llmClient instanceof LLMOperations operations) {
            return operations.executeEntity(buildExecutionContext(prompt, request, context), targetType);
        }
        return llmClient.entity(prompt, targetType);
    }

    private <T extends DomainContext> Mono<String> executeRaw(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        if (llmClient instanceof LLMOperations operations) {
            return operations.execute(buildExecutionContext(prompt, request, context));
        }
        return llmClient.call(prompt);
    }

    private <T extends DomainContext> Flux<String> executeStream(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        if (llmClient instanceof LLMOperations operations) {
            return operations.stream(buildExecutionContext(prompt, request, context));
        }
        return llmClient.stream(prompt);
    }

    private <T extends DomainContext> ExecutionContext buildExecutionContext(
            Prompt prompt,
            AIRequest<T> request,
            PipelineExecutionContext context) {
        ExecutionContext executionContext = ExecutionContext.from(prompt);
        executionContext.setRequestId(request != null ? request.getRequestId() : null);
        String pinnedModelId = resolveStringParameter(request, context, "officialVerificationPinnedModelId");
        Double temperature = resolveDoubleParameter(request, context, "officialVerificationTemperature");
        Double topP = resolveDoubleParameter(request, context, "officialVerificationTopP");
        Integer seed = resolveIntegerParameter(request, context, "officialVerificationSeed");
        Integer maxTokens = resolveIntegerParameter(request, context, "officialVerificationMaxTokens");
        Boolean disableRetries = resolveBooleanParameter(request, context, "officialVerificationDisableRetries");
        Boolean disableOllamaThinking = resolveBooleanParameter(request, context, "officialVerificationDisableOllamaThinking");
        String boundaryMode = resolveStringParameter(request, context, "officialVerificationDecisionBoundaryMode");
        if (boundaryMode == null && (pinnedModelId != null || temperature != null || topP != null || seed != null || maxTokens != null
                || disableRetries != null || disableOllamaThinking != null)) {
            boundaryMode = "OFFICIAL_VERIFICATION_RUNTIME";
        }
        if (pinnedModelId != null && !pinnedModelId.isBlank()) {
            executionContext.setPreferredModel(pinnedModelId);
            recordMetadata(context, executionContext, "officialVerificationPinnedModelId", pinnedModelId);
        }
        if (temperature != null) {
            executionContext.setTemperature(temperature);
            recordMetadata(context, executionContext, "officialVerificationTemperature", temperature);
        }
        if (topP != null) {
            executionContext.setTopP(topP);
            recordMetadata(context, executionContext, "officialVerificationTopP", topP);
        }
        if (seed != null) {
            executionContext.setSeed(seed);
            recordMetadata(context, executionContext, "officialVerificationSeed", seed);
        }
        if (maxTokens != null) {
            executionContext.setMaxTokens(maxTokens);
            recordMetadata(context, executionContext, "officialVerificationMaxTokens", maxTokens);
        }
        if (disableRetries != null) {
            executionContext.addMetadata("disableRetries", disableRetries);
            recordMetadata(context, executionContext, "officialVerificationDisableRetries", disableRetries);
        }
        if (disableOllamaThinking != null) {
            executionContext.addMetadata("disableOllamaThinking", disableOllamaThinking);
            recordMetadata(context, executionContext, "officialVerificationDisableOllamaThinking", disableOllamaThinking);
        }
        if (boundaryMode != null && !boundaryMode.isBlank()) {
            recordMetadata(context, executionContext, "officialVerificationDecisionBoundaryMode", boundaryMode);
        }
        return executionContext;
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

    private <T extends DomainContext> String resolveStringParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String key) {
        Object value = resolveRawParameter(request, context, key);
        if (value instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        return value != null ? String.valueOf(value) : null;
    }

    private <T extends DomainContext> Double resolveDoubleParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String key) {
        Object value = resolveRawParameter(request, context, key);
        if (value instanceof Double number) {
            return number;
        }
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private <T extends DomainContext> Integer resolveIntegerParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String key) {
        Object value = resolveRawParameter(request, context, key);
        if (value instanceof Integer number) {
            return number;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private <T extends DomainContext> Boolean resolveBooleanParameter(
            AIRequest<T> request,
            PipelineExecutionContext context,
            String key) {
        Object value = resolveRawParameter(request, context, key);
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text.trim());
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
}


