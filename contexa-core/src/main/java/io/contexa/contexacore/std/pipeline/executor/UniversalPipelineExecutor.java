package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.*;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

@Slf4j
public class UniversalPipelineExecutor implements PipelineExecutor {

    private final Tracer tracer;
    protected final List<PipelineStep> steps;
    private final LLMExecutionStep llmExecutionStep;
    private final PipelineStep soarToolExecutionStep;
    private final FinalResponseBuilder responseBuilder;

    public UniversalPipelineExecutor(
            Tracer tracer,
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            LLMExecutionStep llmExecutionStep,
            PipelineStep soarToolExecutionStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep) {

        this.tracer = tracer;
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

        long pipelineStartTime = System.currentTimeMillis();

        Span span = tracer.spanBuilder("pipeline.execute")
                .setAttribute("request.id", request.getRequestId())
                .setAttribute("domain", getSupportedDomain())
                .setAttribute("response.type", responseType.getSimpleName())
                .startSpan();

        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addMetadata("targetResponseType", responseType);

        try (Scope scope = span.makeCurrent()) {
            return executeStepsSequentially(request, configuration, context, responseType)
                    .map(ctx -> responseBuilder.build(request, ctx, responseType))
                    .doOnSuccess(response -> {
                        long totalTime = System.currentTimeMillis() - pipelineStartTime;
                        span.setAttribute("duration.ms", totalTime);
                        span.setStatus(StatusCode.OK);
                    })
                    .doOnError(error -> {
                        long totalTime = System.currentTimeMillis() - pipelineStartTime;
                        span.setAttribute("duration.ms", totalTime);
                        span.recordException(error);
                        span.setStatus(StatusCode.ERROR, error.getMessage());
                        log.error("[PIPELINE] Pipeline failed - Request: {} Duration: {}ms - {}",
                                request.getRequestId(), totalTime, error.getMessage(), error);
                    })
                    .doFinally(signalType -> span.end());
        }
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
        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : steps) {
            PipelineStep actualStep;
            if (step == llmExecutionStep && isSoar && soarToolExecutionStep != null) {
                actualStep = soarToolExecutionStep;
            } else {
                actualStep = step;
            }

            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(actualStep, isSoar);

            if (configuration.hasStep(configStep)) {
                final String stepName = actualStep.getStepName();
                final int stepOrder = actualStep.getOrder();

                pipeline = pipeline.flatMap(ctx -> {
                    long stepStart = System.currentTimeMillis();

                    Span stepSpan = tracer.spanBuilder("pipeline.step." + stepName)
                            .setAttribute("step.name", stepName)
                            .setAttribute("step.order", stepOrder)
                            .setAttribute("request.id", request.getRequestId())
                            .startSpan();

                    try (Scope stepScope = stepSpan.makeCurrent()) {
                        return actualStep.execute(request, ctx)
                                .thenReturn(ctx)
                                .doOnSuccess(c -> {
                                    long stepTime = System.currentTimeMillis() - stepStart;
                                    stepSpan.setAttribute("step.duration.ms", stepTime);
                                    stepSpan.setStatus(StatusCode.OK);
                                })
                                .doOnError(error -> {
                                    long stepTime = System.currentTimeMillis() - stepStart;
                                    stepSpan.setAttribute("step.duration.ms", stepTime);
                                    stepSpan.recordException(error);
                                    stepSpan.setStatus(StatusCode.ERROR, error.getMessage());
                                    log.error("[PIPELINE] STEP {} failed: {} ({}ms) - {}",
                                            stepOrder, stepName, stepTime, error.getMessage());
                                })
                                .doFinally(signalType -> stepSpan.end());
                    }
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

        for (PipelineStep step : steps.subList(0, Math.min(3, steps.size()))) {
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(step, isSoar);

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
        if (step.getStepName().equals("LLM_EXECUTION") && isSoar) {
            return PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION;
        }

        return switch (step.getStepName()) {
            case "CONTEXT_RETRIEVAL" -> PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL;
            case "PREPROCESSING" -> PipelineConfiguration.PipelineStep.PREPROCESSING;
            case "PROMPT_GENERATION" -> PipelineConfiguration.PipelineStep.PROMPT_GENERATION;
            case "LLM_EXECUTION" -> PipelineConfiguration.PipelineStep.LLM_EXECUTION;
            case "SOAR_TOOL_EXECUTION" -> PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION;
            case "RESPONSE_PARSING" -> PipelineConfiguration.PipelineStep.RESPONSE_PARSING;
            case "POSTPROCESSING" -> PipelineConfiguration.PipelineStep.POSTPROCESSING;
            default -> throw new IllegalArgumentException("Unknown step: " + step.getStepName());
        };
    }

    @Override
    public String getSupportedDomain() {
        return "UNIVERSAL";
    }

    @Override
    public <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration<T> configuration) {
        return configuration.getSteps().stream()
                .allMatch(step -> step == PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL ||
                        step == PipelineConfiguration.PipelineStep.PREPROCESSING ||
                        step == PipelineConfiguration.PipelineStep.PROMPT_GENERATION ||
                        step == PipelineConfiguration.PipelineStep.LLM_EXECUTION ||
                        step == PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION ||
                        step == PipelineConfiguration.PipelineStep.RESPONSE_PARSING ||
                        step == PipelineConfiguration.PipelineStep.POSTPROCESSING);
    }

    @Override
    public int getPriority() {
        return 100;
    }
}
