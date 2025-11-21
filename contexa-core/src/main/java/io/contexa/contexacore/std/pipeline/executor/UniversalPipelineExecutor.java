package io.contexa.contexacore.std.pipeline.executor;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.*;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

/**
 * 범용 파이프라인 실행자 (리팩토링 버전)
 *
 * 객체 지향 설계 개선:
 * 핸들러 패턴 (Handler Pattern): 각 Step의 실행 로직을 StepExecutionHandler로 캡슐화하여 분리.
 * - DefaultStepExecutionHandler: 일반적인 Step 실행 담당.
 * - PostprocessingStepExecutionHandler: PostprocessingStep의 특수 로직 전담.
 * 빌더 패턴 (Builder Pattern): 복잡한 최종 응답 생성 로직을 FinalResponseBuilder로 분리.
 * 단일 책임 원칙 (SRP): Executor는 파이프라인 '조율'에만 집중하고, 실제 '실행'과 '생성'은 각 전문 객체에 위임.
 */
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

        // 1. 단계들을 순서대로 정렬
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

        // 2. 단계별 실행을 처리할 핸들러 등록
        this.stepHandlers = List.of(
                new PostprocessingStepExecutionHandler(),
                new DefaultStepExecutionHandler()
        );

        // 3. 최종 응답 생성기 초기화
        this.responseBuilder = new FinalResponseBuilder();

        log.info("UniversalPipelineExecutor (Refactored) 초기화 완료: {} 단계, {} 핸들러", steps.size(), stepHandlers.size());
    }

    @Override
    public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            Class<R> responseType) {

        long pipelineStartTime = System.currentTimeMillis();

        // OpenTelemetry Span 시작
        Span span = tracer.spanBuilder("pipeline.execute")
                .setAttribute("request.id", request.getRequestId())
                .setAttribute("domain", getSupportedDomain())
                .setAttribute("response.type", responseType.getSimpleName())
                .startSpan();

        log.info("[PIPELINE] ===== Universal Pipeline 실행 시작 ===== Request: {}", request.getRequestId());

        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addMetadata("targetResponseType", responseType);

        // Span을 Context에 저장하여 하위 단계에서 참조 가능
        try (Scope scope = span.makeCurrent()) {
            return executeStepsSequentially(request, configuration, context, responseType)
                    .map(ctx -> responseBuilder.build(request, ctx, responseType)) // FinalResponseBuilder 사용
                    .doOnSuccess(response -> {
                        long totalTime = System.currentTimeMillis() - pipelineStartTime;
                        span.setAttribute("duration.ms", totalTime);
                        span.setStatus(StatusCode.OK);
                        log.info("[PIPELINE] ===== Pipeline 완료 ===== Request: {} 총 처리시간: {}ms",
                                request.getRequestId(), totalTime);
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
        log.info("[{}] Universal Pipeline 스트리밍 시작: {}", getSupportedDomain(), request.getRequestId());
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

    /**
     * 파이프라인 단계를 순차적으로 실행합니다.
     * 각 단계에 맞는 StepExecutionHandler를 찾아 실행을 위임합니다.
     */
    private <T extends DomainContext, R extends AIResponse> Mono<PipelineExecutionContext> executeStepsSequentially(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            PipelineExecutionContext context,
            Class<R> responseType) {

        log.info("[PIPELINE] ===== 6단계 순차 실행 시작 (Handler 방식) ===== Request: {}", request.getRequestId());

        // 현재 컨텍스트 설정 (SOAR 판별을 위해)
        setCurrentContext(request.getContext());
        
        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : steps) {
            // SOAR 컨텍스트에서 LLM_EXECUTION 대신 SOAR_TOOL_EXECUTION 사용
            PipelineStep actualStep;
            if (step == llmExecutionStep && isSoarContext() && soarToolExecutionStep != null) {
                actualStep = soarToolExecutionStep;
                log.info("SOAR 컨텍스트 감지: LLM_EXECUTION → SOAR_TOOL_EXECUTION 전환");
            } else {
                actualStep = step;
            }

            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(actualStep);

            if (configuration.hasStep(configStep)) {

                final String stepName = actualStep.getStepName();
                final int stepOrder = actualStep.getOrder();
                pipeline = pipeline.flatMap(ctx -> {
                    // 동적 파이프라인: 조건부 실행 확인
                    if (!configuration.shouldExecuteStep(configStep, request, ctx)) {
                        log.info("[PIPELINE] STEP {} 건너뜀 (조건 미충족): {}", stepOrder, stepName);
                        return Mono.just(ctx);
                    }

                    long stepStart = System.currentTimeMillis();

                    // Child Span 생성 (각 파이프라인 단계마다)
                    Span stepSpan = tracer.spanBuilder("pipeline.step." + stepName)
                            .setAttribute("step.name", stepName)
                            .setAttribute("step.order", stepOrder)
                            .setAttribute("request.id", request.getRequestId())
                            .startSpan();

                    log.info("[PIPELINE] STEP {}: {} 시작", stepOrder, stepName);

                    try (Scope stepScope = stepSpan.makeCurrent()) {
//                    StepExecutionHandler handler = findHandlerFor(actualStep);
                        StepExecutionHandler handler = new DefaultStepExecutionHandler();
                        return handler.execute(actualStep, request, configuration, ctx, responseType)
                                .doOnSuccess(c -> {
                                    long stepTime = System.currentTimeMillis() - stepStart;
                                    stepSpan.setAttribute("step.duration.ms", stepTime);
                                    stepSpan.setStatus(StatusCode.OK);
                                    log.info("[PIPELINE] STEP {} 완료: {} ({}ms)", stepOrder, stepName, stepTime);
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
                log.debug("⏭️ [PIPELINE] STEP {} 건너뜀: {} (비활성화)", step.getOrder(), step.getStepName());
            }
        }
        
        // 파이프라인 실행 완료 후 컨텍스트 정리
        return pipeline.doFinally(signal -> clearCurrentContext());
    }

    /**
     * 주어진 Step을 처리할 수 있는 핸들러를 찾습니다.
     */
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

        log.info("[PIPELINE] 스트리밍 전처리 단계 비동기 실행 시작");

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        // 첫 3단계를 비동기로 순차 실행
        for (PipelineStep step : steps.subList(0, Math.min(3, steps.size()))) {
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(step);

            if (configuration.hasStep(configStep) && step.canExecute(request)) {
                final String stepName = step.getStepName();

                pipeline = pipeline.flatMap(ctx -> {
                    log.debug("[PIPELINE] 스트리밍 전처리 단계: {} 시작", stepName);

                    StepExecutionHandler handler = findHandlerFor(step);
                    return handler.execute(step, request, configuration, ctx, null)
                            .doOnSuccess(c -> {
                                log.debug("[{}] {} 완료 (스트리밍용)", getSupportedDomain(), stepName);
                            })
                            .doOnError(error -> {
                                log.error("[PIPELINE] 스트리밍 전처리 단계 {} 실패: {}", stepName, error.getMessage());
                            });
                });
            }
        }

        return pipeline.doOnSuccess(ctx -> {
            log.info("[PIPELINE] 스트리밍 전처리 단계 비동기 실행 완료");
        });
    }

    /**
     * Step 클래스를 PipelineConfiguration.PipelineStep 으로 매핑합니다.
     * SOAR 컨텍스트에서는 LLM_EXECUTION을 SOAR_TOOL_EXECUTION 으로 동적 대체합니다.
     */
    private PipelineConfiguration.PipelineStep getConfigStepForStep(PipelineStep step) {
        // SOAR 컨텍스트에서 LLM_EXECUTION을 SOAR_TOOL_EXECUTION 으로 대체
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
    
    /**
     * 현재 컨텍스트가 SOAR 컨텍스트인지 확인
     * ThreadLocal을 사용하여 현재 실행 중인 컨텍스트 추적
     */
    private static final ThreadLocal<DomainContext> currentContext = new ThreadLocal<>();
    
    /**
     * 현재 컨텍스트 설정 (executeStepsSequentially 시작 시 호출)
     */
    private void setCurrentContext(DomainContext context) {
        currentContext.set(context);
    }
    
    /**
     * 현재 컨텍스트 정리 (executeStepsSequentially 종료 시 호출)
     */
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
        return 100; // 범용 실행자는 낮은 우선순위
    }
}
