package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Slf4j
public abstract class AbstractAIStrategy<T extends DomainContext, R extends AIResponse> implements AIStrategy<T, R> {

    protected final AILabFactory labFactory;

    protected AbstractAIStrategy(AILabFactory labFactory) {
        this.labFactory = labFactory;
    }

    @Override
    public R execute(AIRequest<T> request, Class<R> responseType) throws DiagnosisException {

        try {
            validateRequest(request);
            Object lab = getRequiredLab();
            Object labRequest = convertLabRequest(request);
            return processLabExecution(lab, labRequest, request);

        } catch (DiagnosisException e) {
            log.error("{} strategy execution failed (DiagnosisException): {}",
                    this.getClass().getSimpleName(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("{} strategy execution failed (Exception)",
                    this.getClass().getSimpleName(), e);
            throw new DiagnosisException(
                    getSupportedType().name(),
                    "EXECUTION_ERROR",
                    getExecutionErrorMessage() + e.getMessage(),
                    e
            );
        }
    }

    @Override
    public Mono<R> executeAsync(AIRequest<T> request, Class<R> responseType) throws DiagnosisException {
        return Mono.fromRunnable(() -> validateRequest(request))
                .then(Mono.fromCallable(this::getRequiredLab))
                .flatMap(lab -> {
                    Object labRequest = convertLabRequest(request);

                    return processLabExecutionAsync(lab, labRequest, request)
                            .doOnSuccess(response -> {
                            })
                            .doOnError(error -> {
                                log.error("Async {} strategy execution failed", getSupportedType(), error);
                            });
                })
                .onErrorMap(DiagnosisException.class, e -> e)
                .onErrorMap(Exception.class, e -> new DiagnosisException(
                        getSupportedType().name(),
                        "ASYNC_EXECUTION_ERROR",
                        getAsyncExecutionErrorMessage() + e.getMessage(),
                        e
                ));
    }

    @Override
    public Flux<String> executeStream(AIRequest<T> request, Class<R> responseType) throws DiagnosisException {
        if (!supportsStreaming()) {
            return Flux.error(new DiagnosisException(
                    getSupportedType().name(),
                    "STREAMING_NOT_SUPPORTED",
                    this.getClass().getSimpleName() + " does not support streaming"
            ));
        }

        try {
            validateRequest(request);
            Object lab = getRequiredLab();
            Object labRequest = convertLabRequest(request);

            return processLabExecutionStream(lab, labRequest, request)
                    .doOnNext(chunk -> {
                    })
                    .doOnComplete(() -> {
                    })
                    .doOnError(error -> {
                        log.error("Streaming {} strategy execution failed", getSupportedType(), error);
                    });

        } catch (DiagnosisException e) {
            log.error("Streaming {} strategy execution failed (DiagnosisException): {}",
                    this.getClass().getSimpleName(), e.getMessage());
            return Flux.error(e);
        } catch (Exception e) {
            log.error("Streaming {} strategy execution failed (Exception)",
                    this.getClass().getSimpleName(), e);
            return Flux.error(new DiagnosisException(
                    getSupportedType().name(),
                    "STREAM_EXECUTION_ERROR",
                    getStreamExecutionErrorMessage() + e.getMessage(),
                    e
            ));
        }
    }

    protected Object getRequiredLab() throws DiagnosisException {
        Class<?> labType = getLabType();

        if (!AILab.class.isAssignableFrom(labType)) {
            throw new DiagnosisException(
                    getSupportedType().name(),
                    "INVALID_LAB_TYPE",
                    labType.getSimpleName() + " does not implement the AILab interface"
            );
        }

        Class<? extends AILab<?, ?>> aiLabType = (Class<? extends AILab<?, ?>>) labType;
        Optional<? extends AILab<?, ?>> labOpt = labFactory.getLab(aiLabType);

        if (labOpt.isEmpty()) {
            throw new DiagnosisException(
                    getSupportedType().name(),
                    "LAB_NOT_FOUND",
                    labType.getSimpleName() + " not found"
            );
        }

        return labOpt.get();
    }

    protected abstract void validateRequest(AIRequest<T> request) throws DiagnosisException;

    protected abstract Class<?> getLabType();

    protected abstract Object convertLabRequest(AIRequest<T> request) throws DiagnosisException;

    protected abstract R processLabExecution(Object lab, Object labRequest, AIRequest<T> request) throws Exception;

    protected abstract Mono<R> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<T> originRequest);

    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<T> request) {
        return Flux.error(new UnsupportedOperationException("Streaming is not supported"));
    }

    protected String getExecutionErrorMessage() {
        return getSupportedType().name() + " diagnosis execution error: ";
    }

    protected String getAsyncExecutionErrorMessage() {
        return "Async " + getSupportedType().name() + " diagnosis execution error: ";
    }

    protected String getStreamExecutionErrorMessage() {
        return "Streaming " + getSupportedType().name() + " diagnosis execution error: ";
    }
}