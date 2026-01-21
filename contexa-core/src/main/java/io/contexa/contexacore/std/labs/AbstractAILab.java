package io.contexa.contexacore.std.labs;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
public abstract class AbstractAILab<Req, Res> implements AILab<Req, Res> {

    private final String labId;
    private final String labName;
    protected final Tracer tracer;

    protected AbstractAILab(String labName, Tracer tracer) {
        this.labId = generateLabId();
        this.labName = labName;
        this.tracer = tracer;
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

    @Override
    public Res process(Req request) {
        long startTime = System.currentTimeMillis();

        Span span = tracer.spanBuilder("lab.process")
                .setAttribute("lab.id", labId)
                .setAttribute("lab.name", labName)
                .setAttribute("processing.mode", "sync")
                .startSpan();

        try (Scope scope = span.makeCurrent()) {

            validateRequest(request);
            preProcess(request);

            Res result = doProcess(request);

            postProcess(request, result);

            long duration = System.currentTimeMillis() - startTime;
            span.setAttribute("processing.duration.ms", duration);
            span.setStatus(StatusCode.OK);
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

    @Override
    public Mono<Res> processAsync(Req request) {
        long startTime = System.currentTimeMillis();

        Span span = tracer.spanBuilder("lab.processAsync")
                .setAttribute("lab.id", labId)
                .setAttribute("lab.name", labName)
                .setAttribute("processing.mode", "async")
                .startSpan();

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

    @Override
    public Flux<String> processStream(Req request) {
        if (!supportsStreaming()) {
            return Flux.error(new UnsupportedOperationException(labName + " does not support streaming"));
        }

        long startTime = System.currentTimeMillis();

        Span span = tracer.spanBuilder("lab.processStream")
                .setAttribute("lab.id", labId)
                .setAttribute("lab.name", labName)
                .setAttribute("processing.mode", "stream")
                .startSpan();

        try (Scope scope = span.makeCurrent()) {
            return Flux.defer(() -> {
                        try {
                            validateRequest(request);
                            preProcess(request);
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

    protected abstract Res doProcess(Req request) throws Exception;
    protected Mono<Res> doProcessAsync(Req request) {
        return Mono.fromCallable(() -> doProcess(request));
    }
    protected Flux<String> doProcessStream(Req request) {
        return Flux.error(new UnsupportedOperationException("Streaming not implemented"));
    }

    protected void validateRequest(Req request) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
    }
    protected void preProcess(Req request) {
    }
    protected void postProcess(Req request, Res result) {
    }

    public static class LabProcessingException extends RuntimeException {
        public LabProcessingException(String message) {
            super(message);
        }
        public LabProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}