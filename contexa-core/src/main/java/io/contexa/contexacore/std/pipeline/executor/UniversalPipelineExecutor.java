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
    private final List<PipelineStep> steps;
    private final LLMExecutionStep llmExecutionStep;
    private final PipelineStep soarToolExecutionStep;
    private final List<StepExecutionHandler> stepHandlers;
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

        this.stepHandlers = List.of(
                new PostprocessingStepExecutionHandler(),
                new DefaultStepExecutionHandler()
        );

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
                        log.error("[PIPELINE] ===== Pipeline 실패 ===== Request: {} 총 처리시간: {}ms - {}",
                                request.getRequestId(), totalTime, error.getMessage(), error);
                    })
                    .doFinally(signalType -> span.end());
        }
    }

    @Override
    public <T extends DomainContext> Flux<String> executeStream(AIRequest<T> request, PipelineConfiguration<T> configuration) {
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        return executePreStreamingSteps(request, configuration, context)
                .flatMapMany(ctx -> {
                    if (configuration.hasStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)) {
                        return llmExecutionStep.executeStreaming(request, ctx)
                                .doOnNext(chunk -> log.debug("[{}] 스트리밍 청크: {}", getSupportedDomain(), chunk));
                    }
                    return Flux.just("ERROR: LLM_EXECUTION 단계가 비활성화됨");
                })
                .doOnComplete(() ->
                        log.info("[{}] 스트리밍 완료: {} ({}ms)",
                                getSupportedDomain(), request.getRequestId(), context.getExecutionTime()))
                .doOnError(error ->
                        log.error("[{}] 스트리밍 실패: {} - {}",
                                getSupportedDomain(), request.getRequestId(), error.getMessage(), error));
    }

    private <T extends DomainContext, R extends AIResponse> Mono<PipelineExecutionContext> executeStepsSequentially(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            PipelineExecutionContext context,
            Class<R> responseType) {

        setCurrentContext(request.getContext());

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : steps) {

            PipelineStep actualStep;
            if (step == llmExecutionStep && isSoarContext() && soarToolExecutionStep != null) {
                actualStep = soarToolExecutionStep;
            } else {
                actualStep = step;
            }

            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(actualStep);

            if (configuration.hasStep(configStep)) {

                final String stepName = actualStep.getStepName();
                final int stepOrder = actualStep.getOrder();
                pipeline = pipeline.flatMap(ctx -> {

                    if (!configuration.shouldExecuteStep(configStep, request, ctx)) {
                        return Mono.just(ctx);
                    }

                    long stepStart = System.currentTimeMillis();

                    Span stepSpan = tracer.spanBuilder("pipeline.step." + stepName)
                            .setAttribute("step.name", stepName)
                            .setAttribute("step.order", stepOrder)
                            .setAttribute("request.id", request.getRequestId())
                            .startSpan();

                    try (Scope stepScope = stepSpan.makeCurrent()) {

                        StepExecutionHandler handler = new DefaultStepExecutionHandler();
                        return handler.execute(actualStep, request, configuration, ctx, responseType)
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
                                    log.error("[PIPELINE] STEP {} 실패: {} ({}ms) - {}",
                                            stepOrder, stepName, stepTime, error.getMessage());
                                })
                                .doFinally(signalType -> stepSpan.end());
                    }
                });
            } else {
            }
        }

        return pipeline.doFinally(signal -> clearCurrentContext());
    }

    protected StepExecutionHandler findHandlerFor(PipelineStep step) {
        return stepHandlers.stream()
                .filter(handler -> handler.canHandle(step))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No handler found for step: " + step.getStepName()));
    }

    private <T extends DomainContext> Mono<PipelineExecutionContext> executePreStreamingSteps(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            PipelineExecutionContext context) {

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : steps.subList(0, Math.min(3, steps.size()))) {
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(step);

            if (configuration.hasStep(configStep) && step.canExecute(request)) {
                final String stepName = step.getStepName();

                pipeline = pipeline.flatMap(ctx -> {

                    StepExecutionHandler handler = findHandlerFor(step);
                    return handler.execute(step, request, configuration, ctx, null)
                            .doOnSuccess(c -> {
                            })
                            .doOnError(error -> {
                                log.error("[PIPELINE] 스트리밍 전처리 단계 {} 실패: {}", stepName, error.getMessage());
                            });
                });
            }
        }

        return pipeline.doOnSuccess(ctx -> {
        });
    }

    private PipelineConfiguration.PipelineStep getConfigStepForStep(PipelineStep step) {

        if (step.getStepName().equals("LLM_EXECUTION") && isSoarContext()) {
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

    private static final ThreadLocal<DomainContext> currentContext = new ThreadLocal<>();

    private void setCurrentContext(DomainContext context) {
        currentContext.set(context);
    }

    private void clearCurrentContext() {
        currentContext.remove();
    }

    private boolean isSoarContext() {
        DomainContext context = currentContext.get();
        return context instanceof SoarContext;
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
