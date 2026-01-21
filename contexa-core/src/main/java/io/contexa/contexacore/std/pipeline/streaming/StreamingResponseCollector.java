package io.contexa.contexacore.std.pipeline.streaming;

public interface StreamingResponseCollector {
    void collect(String chunk);
    String getFullResponse();
    void reset();
    boolean isComplete();
}