package io.contexa.contexacore.std.pipeline.executor;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.*;
import io.contexa.contexacore.std.pipeline.streaming.StreamingPipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.util.List;
import java.util.stream.Stream;

/**
 * UniversalPipelineExecutor를 확장한 스트리밍 전용 실행자
 */
@Slf4j
public class StreamingUniversalPipelineExecutor extends UniversalPipelineExecutor {

    private final List<PipelineStep> orderedSteps;
    private final ObjectMapper objectMapper;

    // 완전한 생성자
    public StreamingUniversalPipelineExecutor(
            Tracer tracer,
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            LLMExecutionStep llmExecutionStep,
            PipelineStep soarToolExecutionStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep,
            StreamingLLMExecutionStep streamingLLMStep,
            ObjectMapper objectMapper) {

        super(tracer, contextRetrievalStep, preprocessingStep, promptGenerationStep,
                llmExecutionStep, soarToolExecutionStep, responseParsingStep, postprocessingStep);

        this.objectMapper = objectMapper;

        // 스트리밍용 단계 순서 (4단계를 streamingLLMStep으로 대체)
        this.orderedSteps = Stream.of(
                        contextRetrievalStep,
                        preprocessingStep,
                        promptGenerationStep,
                        streamingLLMStep,
                        responseParsingStep,
                        postprocessingStep
                )
                .sorted((a, b) -> Integer.compare(a.getOrder(), b.getOrder()))
                .toList();
    }

    @Override
    public <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration) {

        log.info("[STREAMING-PIPELINE] 통합 스트리밍 파이프라인 시작: {}", request.getRequestId());

        // 스트리밍 전용 컨텍스트 생성
        StreamingPipelineExecutionContext context =
                new StreamingPipelineExecutionContext(request.getRequestId());
        context.enableStreamingMode();

        // 스트림 Sink 생성
        Sinks.Many<String> sink = Sinks.many().multicast().onBackpressureBuffer();
        context.setStreamSink(sink);

        // 6단계 전체 실행 (백그라운드)
        executeFullPipelineWithStreaming(request, configuration, context).subscribe(
                null,
                error -> {
                    log.error("스트리밍 파이프라인 오류", error);
                    sink.tryEmitError(error);
                },
                () -> {
                    log.info("스트리밍 파이프라인 완료");

                    // 최종 결과 전송
                    AIResponse finalResponse = context.getStepResult(
                            PipelineConfiguration.PipelineStep.POSTPROCESSING,
                            AIResponse.class
                    );

                    if (finalResponse != null) {
                        try {
                            // JSON 변환
                            String jsonResponse = objectMapper.writeValueAsString(finalResponse);
                            sink.tryEmitNext("###FINAL_RESPONSE###" + jsonResponse);
                        } catch (Exception e) {
                            log.error("최종 응답 JSON 변환 오류", e);
                        }
                    }

                    sink.tryEmitComplete();
                }
        );

        return sink.asFlux();
    }

    private <T extends DomainContext> Mono<Void> executeFullPipelineWithStreaming(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            StreamingPipelineExecutionContext context) {

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        // 6단계 순차 실행 (스트리밍용 단계 사용)
        for (PipelineStep step : orderedSteps) {
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(step);

            if (configuration.hasStep(configStep)) {
                final String stepName = step.getStepName();
                final int stepOrder = step.getOrder();

                pipeline = pipeline.flatMap(ctx -> {
                    long stepStart = System.currentTimeMillis();
                    log.info("[STREAMING-PIPELINE] STEP {}: {} 시작", stepOrder, stepName);
                    StepExecutionHandler handler = super.findHandlerFor(step);
                    return handler.execute(step, request, configuration, ctx, AIResponse.class)
                            .doOnSuccess(c -> {
                                long stepTime = System.currentTimeMillis() - stepStart;
                                log.info("[STREAMING-PIPELINE] STEP {} 완료: {} ({}ms)",
                                        stepOrder, stepName, stepTime);
                            })
                            .doOnError(error -> {
                                long stepTime = System.currentTimeMillis() - stepStart;
                                log.error("[STREAMING-PIPELINE] STEP {} 실패: {} ({}ms) - {}",
                                        stepOrder, stepName, stepTime, error.getMessage());
                            });
                });
            }
        }

        return pipeline.then();
    }

    private PipelineConfiguration.PipelineStep getConfigStepForStep(PipelineStep step) {
        return switch (step.getStepName()) {
            case "CONTEXT_RETRIEVAL" -> PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL;
            case "PREPROCESSING" -> PipelineConfiguration.PipelineStep.PREPROCESSING;
            case "PROMPT_GENERATION" -> PipelineConfiguration.PipelineStep.PROMPT_GENERATION;
            case "LLM_EXECUTION", "STREAMING_LLM_EXECUTION" -> PipelineConfiguration.PipelineStep.LLM_EXECUTION;
            case "RESPONSE_PARSING" -> PipelineConfiguration.PipelineStep.RESPONSE_PARSING;
            case "POSTPROCESSING" -> PipelineConfiguration.PipelineStep.POSTPROCESSING;
            default -> throw new IllegalArgumentException("Unknown step: " + step.getStepName());
        };
    }

    @Override
    public String getSupportedDomain() {
        return "STREAMING-UNIVERSAL";
    }
}