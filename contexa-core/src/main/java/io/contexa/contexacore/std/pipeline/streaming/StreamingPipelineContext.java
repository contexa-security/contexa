package io.contexa.contexacore.std.pipeline.streaming;

import reactor.core.publisher.Sinks;


public interface StreamingPipelineContext {
    boolean isStreamingMode();
    void enableStreamingMode();
    void disableStreamingMode(); 
    void setResponseCollector(StreamingResponseCollector collector);
    StreamingResponseCollector getResponseCollector();
    void setStreamSink(Sinks.Many<String> sink);
    Sinks.Many<String> getStreamSink();
}