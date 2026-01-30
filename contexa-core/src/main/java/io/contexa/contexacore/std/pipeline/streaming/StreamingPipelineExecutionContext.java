package io.contexa.contexacore.std.pipeline.streaming;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Sinks;

@Getter
@Setter
public class StreamingPipelineExecutionContext extends PipelineExecutionContext
        implements StreamingPipelineContext {

    private boolean streamingMode = false;
    private Sinks.Many<String> streamSink;

    public StreamingPipelineExecutionContext(String requestId) {
        super(requestId);
    }

    @Override
    public void enableStreamingMode() {
        this.streamingMode = true;
    }

    @Override
    public boolean isStreamingMode() {
        return streamingMode;
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
