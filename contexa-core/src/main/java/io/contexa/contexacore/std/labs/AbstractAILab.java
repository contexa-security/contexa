package io.contexa.contexacore.std.labs;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * AI Lab 추상 클래스
 *
 * 모든 AI Lab의 공통 로직을 포함하는 Template Method Pattern 구현
 * 기존 AbstractIAMLab의 기능을 포함하면서 새로운 표준 API 제공
 *
 * @param <Req> 요청 타입
 * @param <Res> 응답 타입
 */
@Slf4j
public abstract class AbstractAILab<Req, Res> implements AILab<Req, Res> {

    private final String labId;
    private final String labName;
    protected final Tracer tracer;

    protected AbstractAILab(String labName, Tracer tracer) {
        this.labId = generateLabId();
        this.labName = labName;
        this.tracer = tracer;

        log.info("AI Lab initialized: {} [{}]", labName, labId);
    }

    private String generateLabId() {
        return "lab-" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public final String getLabId() {
        return labId;
    }

    @Override
    public final String getLabName() {
        return labName;
    }

    /**
     * Template Method: 동기 처리
     * 공통 전처리/후처리 로직을 포함
     */
    @Override
    public Res process(Req request) {
        long startTime = System.currentTimeMillis();

        // OpenTelemetry Span 시작
        Span span = tracer.spanBuilder("lab.process")
                .setAttribute("lab.id", labId)
                .setAttribute("lab.name", labName)
                .setAttribute("processing.mode", "sync")
                .startSpan();

        log.info("{} processing request synchronously", labName);

        try (Scope scope = span.makeCurrent()) {
            // 전처리
            validateRequest(request);
            preProcess(request);

            // 실제 처리 (하위 클래스에서 구현)
            Res result = doProcess(request);

            // 후처리
            postProcess(request, result);

            long duration = System.currentTimeMillis() - startTime;
            span.setAttribute("processing.duration.ms", duration);
            span.setStatus(StatusCode.OK);

            log.info("{} processing completed successfully ({}ms)", labName, duration);
            return result;

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            span.setAttribute("processing.duration.ms", duration);
            span.recordException(e);
            span.setStatus(StatusCode.ERROR, e.getMessage());

            log.error("{} processing failed ({}ms)", labName, duration, e);
            throw new LabProcessingException(labName + " processing failed: " + e.getMessage(), e);
        } finally {
            span.end();
        }
    }

    /**
     * Template Method: 비동기 처리
     */
    @Override
    public Mono<Res> processAsync(Req request) {
        long startTime = System.currentTimeMillis();

        // OpenTelemetry Span 시작
        Span span = tracer.spanBuilder("lab.processAsync")
                .setAttribute("lab.id", labId)
                .setAttribute("lab.name", labName)
                .setAttribute("processing.mode", "async")
                .startSpan();

        log.info("{} processing request asynchronously", labName);

        try (Scope scope = span.makeCurrent()) {
            return Mono.fromCallable(() -> {
                        validateRequest(request);
                        preProcess(request);
                        return request;
                    })
                    .flatMap(this::doProcessAsync)
                    .doOnNext(result -> postProcess(request, result))
                    .doOnSuccess(result -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("processing.duration.ms", duration);
                        span.setStatus(StatusCode.OK);
                        log.info("{} async processing completed successfully ({}ms)", labName, duration);
                    })
                    .doOnError(error -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("processing.duration.ms", duration);
                        span.recordException(error);
                        span.setStatus(StatusCode.ERROR, error.getMessage());
                        log.error("{} async processing failed ({}ms)", labName, duration, error);
                    })
                    .doFinally(signalType -> span.end())
                    .onErrorMap(e -> new LabProcessingException(labName + " async processing failed: " + e.getMessage(), e));
        }
    }

    /**
     * Template Method: 스트리밍 처리
     */
    @Override
    public Flux<String> processStream(Req request) {
        if (!supportsStreaming()) {
            return Flux.error(new UnsupportedOperationException(labName + " does not support streaming"));
        }

        long startTime = System.currentTimeMillis();

        // OpenTelemetry Span 시작
        Span span = tracer.spanBuilder("lab.processStream")
                .setAttribute("lab.id", labId)
                .setAttribute("lab.name", labName)
                .setAttribute("processing.mode", "stream")
                .startSpan();

        log.info("{} processing request in streaming mode", labName);

        try (Scope scope = span.makeCurrent()) {
            return Flux.defer(() -> {
                        try {
                            validateRequest(request);
                            preProcess(request);
                            log.info("{} processing request in streaming mode", labName);
                            return doProcessStream(request);
                        } catch (Exception e) {
                            return Flux.error(new LabProcessingException(labName + " streaming failed: " + e.getMessage(), e));
                        }
                    })
                    .doOnNext(chunk -> log.debug("{} streaming chunk: {}", labName,
                            chunk.length() > 50 ? chunk.substring(0, 50) + "..." : chunk))
                    .doOnComplete(() -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("processing.duration.ms", duration);
                        span.setStatus(StatusCode.OK);
                        log.info("{} streaming completed ({}ms)", labName, duration);
                    })
                    .doOnError(error -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("processing.duration.ms", duration);
                        span.recordException(error);
                        span.setStatus(StatusCode.ERROR, error.getMessage());
                        log.error("{} streaming failed ({}ms)", labName, duration, error);
                    })
                    .doFinally(signalType -> span.end());
        }
    }

    // ==================== 하위 클래스에서 구현해야 하는 추상 메서드 ====================

    /**
     * 실제 동기 처리 로직
     */
    protected abstract Res doProcess(Req request) throws Exception;

    /**
     * 실제 비동기 처리 로직
     * 기본 구현은 동기 메서드를 Mono로 래핑
     */
    protected Mono<Res> doProcessAsync(Req request) {
        return Mono.fromCallable(() -> doProcess(request));
    }

    /**
     * 실제 스트리밍 처리 로직
     * 스트리밍을 지원하는 Lab만 구현
     */
    protected Flux<String> doProcessStream(Req request) {
        return Flux.error(new UnsupportedOperationException("Streaming not implemented"));
    }

    // ==================== 선택적 오버라이드 메서드 ====================

    /**
     * 요청 검증
     */
    protected void validateRequest(Req request) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
    }

    /**
     * 전처리 로직
     */
    protected void preProcess(Req request) {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * 후처리 로직
     */
    protected void postProcess(Req request, Res result) {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * Lab 처리 중 발생하는 예외
     */
    public static class LabProcessingException extends RuntimeException {
        public LabProcessingException(String message) {
            super(message);
        }

        public LabProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}