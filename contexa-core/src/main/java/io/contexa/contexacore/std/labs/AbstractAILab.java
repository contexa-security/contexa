package io.contexa.contexacore.std.labs;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
public abstract class AbstractAILab<Req, Res> implements AILab<Req, Res> {

    private final String labId;
    private final String labName;

    protected AbstractAILab(String labName) {
        this.labId = generateLabId();
        this.labName = labName;
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

        try {
            validateRequest(request);
            preProcess(request);

            Res result = doProcess(request);

            postProcess(request, result);

            return result;

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("{} processing failed ({}ms)", labName, duration, e);
            throw new LabProcessingException(labName + " processing failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Mono<Res> processAsync(Req request) {
        long startTime = System.currentTimeMillis();

        return Mono.fromCallable(() -> {
                    validateRequest(request);
                    preProcess(request);
                    return request;
                })
                .flatMap(this::doProcessAsync)
                .doOnNext(result -> postProcess(request, result))
                .doOnError(error -> {
                    long duration = System.currentTimeMillis() - startTime;
                    log.error("{} async processing failed ({}ms)", labName, duration, error);
                })
                .onErrorMap(e -> new LabProcessingException(labName + " async processing failed: " + e.getMessage(), e));
    }

    @Override
    public Flux<String> processStream(Req request) {
        if (!supportsStreaming()) {
            return Flux.error(new UnsupportedOperationException(labName + " does not support streaming"));
        }

        long startTime = System.currentTimeMillis();

        return Flux.defer(() -> {
                    try {
                        validateRequest(request);
                        preProcess(request);
                        return doProcessStream(request);
                    } catch (Exception e) {
                        return Flux.error(new LabProcessingException(labName + " streaming failed: " + e.getMessage(), e));
                    }
                })
                .doOnError(error -> {
                    long duration = System.currentTimeMillis() - startTime;
                    log.error("{} streaming failed ({}ms)", labName, duration, error);
                });
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
