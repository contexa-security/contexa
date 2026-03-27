package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Qualifier;
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

        if (finalTargetType != null) {
            return preparePrompt(context)
                    .flatMap(prompt -> llmClient.entity(prompt, finalTargetType))
                    .doOnSuccess(response -> {
                        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                        context.addMetadata("structuredOutputComplete", true);
                    })
                    .cast(Object.class)
                    .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                    .onErrorResume(error -> {
                        log.error("[PIPELINE-STEP] Structured output execution failed. Attempting String fallback. Request: {}", request.getRequestId());

                        return Mono.just(error.getMessage());
                    });
        }

        return preparePrompt(context)
                .flatMap(llmClient::call)
                .doOnSuccess(response -> {
                    context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                })
                .cast(Object.class)
                .doOnError(error -> logError(request.getRequestId(), error, stepStartTime))
                .onErrorResume(error -> {
                    log.error("[PIPELINE-STEP] LLM execution failed. Request: {}", request.getRequestId());
                    return Mono.error(error);
                });
    }

    public <T extends DomainContext> Flux<String> executeStreaming(AIRequest<T> request, PipelineExecutionContext context) {

        return preparePrompt(context)
                .flatMapMany(prompt -> {
                    return llmClient.stream(prompt);
                })
                .doOnError(error -> log.error("[PIPELINE-STEP] Streaming execution failed. Request: {}", request.getRequestId(), error));
    }

    /**
     * Prepares the prompt from the pipeline execution context.
     * This method can be reused by subclasses for prompt preparation.
     *
     * @param context the pipeline execution context containing the prompt generation result
     * @return Mono of the prepared Prompt
     */
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
