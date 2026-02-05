package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingPipelineContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingPipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Qualifier("streamingLLMExecutionStep")
public class StreamingLLMExecutionStep extends LLMExecutionStep {

    public StreamingLLMExecutionStep(ToolCapableLLMClient llmClient) {
        super(llmClient);
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request,
            PipelineExecutionContext context) {

        if (context instanceof StreamingPipelineContext streamingContext) {
            if (streamingContext.isStreamingMode()) {
                return executeWithStreaming(request, streamingContext);
            }
        }

        return super.execute(request, context);
    }

    private <T extends DomainContext> Mono<Object> executeWithStreaming(
            AIRequest<T> request,
            StreamingPipelineContext context) {

        StreamingPipelineExecutionContext executionContext = (StreamingPipelineExecutionContext) context;

        return preparePrompt(executionContext)
                
                .flatMap(prompt -> {
                    StringBuilder rawResponseCollector = new StringBuilder();

                    Flux<String> llmStream = getLlmClient().stream(prompt);

                    return llmStream
                            .doOnNext(chunk -> {
                                if (chunk.startsWith(StreamingProtocol.STREAMING_MARKER)) {
                                    String streamingText = chunk.substring(StreamingProtocol.STREAMING_MARKER.length());
                                    rawResponseCollector.append(streamingText);

                                    if (context.getStreamSink() != null && context.isStreamingMode()) {
                                        context.getStreamSink().tryEmitNext(streamingText);
                                    }
                                } else {
                                    rawResponseCollector.append(chunk);
                                    if (context.getStreamSink() != null && context.isStreamingMode()) {
                                        context.getStreamSink().tryEmitNext(chunk);
                                    }
                                }
                            })
                            .doOnComplete(() -> {
                                String fullRawResponse = rawResponseCollector.toString();
                                executionContext.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, fullRawResponse);
                            })
                            .then(Mono.just(rawResponseCollector.toString()))
                            .cast(Object.class);
                });
    }
}