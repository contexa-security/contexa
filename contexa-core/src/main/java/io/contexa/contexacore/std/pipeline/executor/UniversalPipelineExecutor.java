package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.*;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

@Slf4j
public class UniversalPipelineExecutor implements PipelineExecutor {

    private static final Set<PipelineConfiguration.PipelineStep> PRE_STREAMING_STEPS = EnumSet.of(
            PipelineConfiguration.PipelineStep.PREPROCESSING,
            PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
            PipelineConfiguration.PipelineStep.PROMPT_GENERATION
    );

    private static final Set<PipelineConfiguration.PipelineStep> SUPPORTED_STEPS = EnumSet.of(
            PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
            PipelineConfiguration.PipelineStep.PREPROCESSING,
            PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
            PipelineConfiguration.PipelineStep.LLM_EXECUTION,
            PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION,
            PipelineConfiguration.PipelineStep.RESPONSE_PARSING,
            PipelineConfiguration.PipelineStep.POSTPROCESSING
    );

    protected final List<PipelineStep> steps;
    private final LLMExecutionStep llmExecutionStep;
    private final PipelineStep soarToolExecutionStep;
    private final FinalResponseBuilder responseBuilder;

    public UniversalPipelineExecutor(
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            LLMExecutionStep llmExecutionStep,
            PipelineStep soarToolExecutionStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep) {

        this.llmExecutionStep = llmExecutionStep;
        this.soarToolExecutionStep = soarToolExecutionStep;

        this.steps = Stream.of(
                        contextRetrievalStep,
                        preprocessingStep,
                        promptGenerationStep,
                        llmExecutionStep,
                        responseParsingStep,
                        postprocessingStep
                )
                .sorted((a, b) -> Integer.compare(a.getOrder(), b.getOrder()))
                .toList();

        this.responseBuilder = new FinalResponseBuilder();
    }

    @Override
    public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            Class<R> responseType) {

        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addMetadata("targetResponseType", responseType);

        return executeStepsSequentially(request, configuration, context, responseType)
                .map(ctx -> responseBuilder.build(request, ctx, responseType))
                .doOnError(error ->
                        log.error("[PIPELINE] Pipeline failed - Request: {} - {}",
                                request.getRequestId(), error.getMessage(), error));
    }

    @Override
    public <T extends DomainContext> Flux<String> executeStream(AIRequest<T> request, PipelineConfiguration<T> configuration) {
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        boolean isSoar = request.getContext() instanceof SoarContext;

        return executePreStreamingSteps(request, configuration, context, isSoar)
                .flatMapMany(ctx -> {
                    if (configuration.hasStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)) {
                        return llmExecutionStep.executeStreaming(request, ctx);
                    }
                    return Flux.just("ERROR: LLM_EXECUTION step is disabled");
                })
                .doOnError(error ->
                        log.error("[{}] Streaming failed: {} - {}",
                                getSupportedDomain(), request.getRequestId(), error.getMessage(), error));
    }

    private <T extends DomainContext, R extends AIResponse> Mono<PipelineExecutionContext> executeStepsSequentially(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            PipelineExecutionContext context,
            Class<R> responseType) {

        boolean isSoar = request.getContext() instanceof SoarContext;
        return executeStepsWithConfig(request, configuration, context, steps, isSoar, "PIPELINE");
    }

    /**
     * Resolves the actual step to execute, allowing subclasses to customize step resolution.
     * Default implementation substitutes SOAR tool execution step when applicable.
     *
     * @param step the original pipeline step
     * @param isSoar whether the request is a SOAR context
     * @return the resolved step to execute
     */
    protected PipelineStep resolveActualStep(PipelineStep step, boolean isSoar) {
        if (step == llmExecutionStep && isSoar && soarToolExecutionStep != null) {
            return soarToolExecutionStep;
        }
        return step;
    }

    /**
     * Executes pipeline steps sequentially with configurable step list and log prefix.
     * This method can be reused by subclasses for different step configurations.
     *
     * @param request the AI request
     * @param configuration the pipeline configuration
     * @param context the execution context
     * @param stepsToExecute the list of steps to execute
     * @param isSoar whether the request is a SOAR context
     * @param logPrefix the log prefix for error messages
     * @return Mono of the execution context after all steps complete
     */
    protected <T extends DomainContext> Mono<PipelineExecutionContext> executeStepsWithConfig(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            PipelineExecutionContext context,
            List<PipelineStep> stepsToExecute,
            boolean isSoar,
            String logPrefix) {

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : stepsToExecute) {
            PipelineStep actualStep = resolveActualStep(step, isSoar);
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(actualStep, isSoar);

            if (configuration.hasStep(configStep)) {
                final String stepName = actualStep.getStepName();
                final int stepOrder = actualStep.getOrder();

                pipeline = pipeline.flatMap(ctx -> {
                    long stepStart = System.currentTimeMillis();

                    return actualStep.execute(request, ctx)
                            .thenReturn(ctx)
                            .doOnError(error -> {
                                long stepTime = System.currentTimeMillis() - stepStart;
                                log.error("[{}] STEP {} failed: {} ({}ms) - {}",
                                        logPrefix, stepOrder, stepName, stepTime, error.getMessage());
                            });
                });
            }
        }

        return pipeline;
    }

    private <T extends DomainContext> Mono<PipelineExecutionContext> executePreStreamingSteps(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            PipelineExecutionContext context,
            boolean isSoar) {

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : steps) {
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(step, isSoar);

            if (!PRE_STREAMING_STEPS.contains(configStep)) {
                continue;
            }

            if (configuration.hasStep(configStep) && step.canExecute(request)) {
                final String stepName = step.getStepName();

                pipeline = pipeline.flatMap(ctx ->
                        step.execute(request, ctx)
                                .thenReturn(ctx)
                                .doOnError(error ->
                                        log.error("[PIPELINE] Pre-streaming step {} failed: {}", stepName, error.getMessage()))
                );
            }
        }

        return pipeline;
    }

    protected PipelineConfiguration.PipelineStep getConfigStepForStep(PipelineStep step, boolean isSoar) {
        if (step.getConfigStep() == PipelineConfiguration.PipelineStep.LLM_EXECUTION && isSoar) {
            return PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION;
        }
        return step.getConfigStep();
    }

    @Override
    public String getSupportedDomain() {
        return "UNIVERSAL";
    }

    @Override
    public <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration<T> configuration) {
        return SUPPORTED_STEPS.containsAll(configuration.getSteps());
    }

    @Override
    public int getPriority() {
        return 100;
    }
}
