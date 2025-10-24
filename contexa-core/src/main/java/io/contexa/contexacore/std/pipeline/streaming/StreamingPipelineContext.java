package io.contexa.contexacore.std.pipeline.streaming;

import reactor.core.publisher.Sinks;

/**
 * 스트리밍 모드 파이프라인 실행을 위한 컨텍스트
 */
public interface StreamingPipelineContext {
    boolean isStreamingMode();
    void enableStreamingMode();
    void disableStreamingMode(); // 스트리밍 비활성화 메서드 추가
    void setResponseCollector(StreamingResponseCollector collector);
    StreamingResponseCollector getResponseCollector();
    void setStreamSink(Sinks.Many<String> sink);
    Sinks.Many<String> getStreamSink();
}