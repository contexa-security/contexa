package io.contexa.contexacore.std.pipeline.streaming;

/**
 * LLM 스트리밍 응답 수집기
 */
public interface StreamingResponseCollector {
    void collect(String chunk);
    String getFullResponse();
    void reset();
    boolean isComplete();
}