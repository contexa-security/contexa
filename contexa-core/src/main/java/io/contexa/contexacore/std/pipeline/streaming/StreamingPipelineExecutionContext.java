package io.contexa.contexacore.std.pipeline.streaming;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Sinks;

/**
 * PipelineExecutionContext를 확장한 스트리밍 전용 컨텍스트
 */
@Getter
@Setter
public class StreamingPipelineExecutionContext extends PipelineExecutionContext
        implements StreamingPipelineContext {

    private boolean streamingMode = false;
    private StreamingResponseCollector responseCollector;
    private Sinks.Many<String> streamSink;

    public StreamingPipelineExecutionContext(String requestId) {
        super(requestId);
        this.responseCollector = new DefaultStreamingResponseCollector();
    }

    @Override
    public void enableStreamingMode() {
        this.streamingMode = true;
    }

    @Override
    public void disableStreamingMode() {
        this.streamingMode = false;
    }

    @Override
    public boolean isStreamingMode() {
        return streamingMode;
    }

    @Override
    public void setResponseCollector(StreamingResponseCollector collector) {
        this.responseCollector = collector;
    }

    @Override
    public StreamingResponseCollector getResponseCollector() {
        return responseCollector;
    }

    @Override
    public void setStreamSink(Sinks.Many<String> sink) {
        this.streamSink = sink;
    }

    @Override
    public Sinks.Many<String> getStreamSink() {
        return streamSink;
    }
}