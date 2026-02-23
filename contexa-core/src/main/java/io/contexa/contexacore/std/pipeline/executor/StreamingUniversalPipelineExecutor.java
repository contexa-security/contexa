package io.contexa.contexacore.std.pipeline.executor;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.*;
import io.contexa.contexacore.std.pipeline.streaming.StreamingPipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.domain.SoarContext;
import lombok.extern.slf4j.Slf4j;
import reactor.core.Disposable;
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
            ContextRetrievalStep contextRetrievalStep,
            PreprocessingStep preprocessingStep,
            PromptGenerationStep promptGenerationStep,
            LLMExecutionStep llmExecutionStep,
            PipelineStep soarToolExecutionStep,
            ResponseParsingStep responseParsingStep,
            PostprocessingStep postprocessingStep,
            StreamingLLMExecutionStep streamingLLMStep,
            ObjectMapper objectMapper) {

        super(contextRetrievalStep, preprocessingStep, promptGenerationStep,
                llmExecutionStep, soarToolExecutionStep, responseParsingStep, postprocessingStep);

        this.objectMapper = objectMapper;

        this.streamingOrderedSteps = Stream.of(
                        contextRetrievalStep,
                        preprocessingStep,
                        promptGenerationStep,
                        streamingLLMStep
                )
                .sorted((a, b) -> Integer.compare(a.getOrder(), b.getOrder()))
                .toList();
    }

    @Override
    public <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request,
            PipelineConfiguration configuration) {

        boolean isSoar = request.getContext() instanceof SoarContext;
        if (isSoar) {
            // SOAR requests fallback to non-streaming pipeline for approval gate support
            return execute(request, configuration, AIResponse.class)
                    .map(response -> {
                        try {
                            return objectMapper.writeValueAsString(response);
                        } catch (Exception e) {
                            log.error("Failed to serialize SOAR fallback response", e);
                            return "{}";
                        }
                    })
                    .flux();
        }

        return Flux.defer(() -> {
            StreamingPipelineExecutionContext context =
                    new StreamingPipelineExecutionContext(request.getRequestId());
            context.enableStreamingMode();

            Sinks.Many<String> sink = Sinks.many().multicast().onBackpressureBuffer();
            context.setStreamSink(sink);

            Disposable disposable = executeFullPipelineWithStreaming(request, configuration, context, false)
                    .doOnSuccess(v -> {
                        AIResponse finalResponse = context.getStepResult(
                                PipelineConfiguration.PipelineStep.POSTPROCESSING,
                                AIResponse.class
                        );

                        if (finalResponse != null) {
                            try {
                                String jsonResponse = objectMapper.writeValueAsString(finalResponse);
                                sink.tryEmitNext(StreamingProtocol.FINAL_RESPONSE_MARKER + jsonResponse);
                            } catch (Exception e) {
                                log.error("Failed to convert final response to JSON", e);
                            }
                        }
                        sink.tryEmitComplete();
                    })
                    .doOnError(error -> {
                        log.error("Streaming pipeline error", error);
                        sink.tryEmitError(error);
                    })
                    .subscribe();

            return sink.asFlux()
                    .doOnCancel(disposable::dispose);
        });
    }

    private <T extends DomainContext> Mono<Void> executeFullPipelineWithStreaming(
            AIRequest<T> request,
            PipelineConfiguration configuration,
            StreamingPipelineExecutionContext context,
            boolean isSoar) {

        return executeStepsWithConfig(request, configuration, context, streamingOrderedSteps, isSoar, "STREAMING-PIPELINE")
                .then();
    }

    @Override
    public String getSupportedDomain() {
        return "STREAMING-UNIVERSAL";
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }
}
