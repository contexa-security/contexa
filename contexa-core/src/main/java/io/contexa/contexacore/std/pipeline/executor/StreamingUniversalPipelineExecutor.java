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
import io.contexa.contexacore.domain.SoarContext;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.util.List;
import java.util.stream.Stream;

@Slf4j
public class StreamingUniversalPipelineExecutor extends UniversalPipelineExecutor {

    private final List<PipelineStep> streamingOrderedSteps;
    private final ObjectMapper objectMapper;

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

        this.streamingOrderedSteps = Stream.of(
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

        StreamingPipelineExecutionContext context =
                new StreamingPipelineExecutionContext(request.getRequestId());
        context.enableStreamingMode();

        Sinks.Many<String> sink = Sinks.many().multicast().onBackpressureBuffer();
        context.setStreamSink(sink);

        boolean isSoar = request.getContext() instanceof SoarContext;

        executeFullPipelineWithStreaming(request, configuration, context, isSoar).subscribe(
                null,
                error -> {
                    log.error("Streaming pipeline error", error);
                    sink.tryEmitError(error);
                },
                () -> {
                    AIResponse finalResponse = context.getStepResult(
                            PipelineConfiguration.PipelineStep.POSTPROCESSING,
                            AIResponse.class
                    );

                    if (finalResponse != null) {
                        try {
                            String jsonResponse = objectMapper.writeValueAsString(finalResponse);
                            sink.tryEmitNext("###FINAL_RESPONSE###" + jsonResponse);
                        } catch (Exception e) {
                            log.error("Failed to convert final response to JSON", e);
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
            StreamingPipelineExecutionContext context,
            boolean isSoar) {

        Mono<PipelineExecutionContext> pipeline = Mono.just(context);

        for (PipelineStep step : streamingOrderedSteps) {
            PipelineConfiguration.PipelineStep configStep = getConfigStepForStep(step, isSoar);

            if (configuration.hasStep(configStep)) {
                final String stepName = step.getStepName();
                final int stepOrder = step.getOrder();

                pipeline = pipeline.flatMap(ctx -> {
                    long stepStart = System.currentTimeMillis();

                    return step.execute(request, ctx)
                            .thenReturn(ctx)
                            .doOnError(error -> {
                                long stepTime = System.currentTimeMillis() - stepStart;
                                log.error("[STREAMING-PIPELINE] STEP {} failed: {} ({}ms) - {}",
                                        stepOrder, stepName, stepTime, error.getMessage());
                            });
                });
            }
        }

        return pipeline.then();
    }

    @Override
    public String getSupportedDomain() {
        return "STREAMING-UNIVERSAL";
    }
}
