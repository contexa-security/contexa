package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration.PipelineStep;
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
            Object labRequest = buildLabRequest(request);
            return processLabExecution(lab, labRequest, request);

        } catch (DiagnosisException e) {
            log.error("{} 전략 실행 실패 (DiagnosisException): {}",
                    this.getClass().getSimpleName(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("{} 전략 실행 실패 (Exception)",
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
                    Object labRequest = buildLabRequest(request);

                    return processLabExecutionAsync(lab, labRequest, request)
                            .doOnSuccess(response -> {
                            })
                            .doOnError(error -> {
                                log.error("비동기 {} 전략 실행 실패", getSupportedType(), error);
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
                    this.getClass().getSimpleName() + "는 스트리밍을 지원하지 않습니다"
            ));
        }

        try {
            validateRequest(request);
            Object lab = getRequiredLab();
            Object labRequest = buildLabRequest(request);

            return processLabExecutionStream(lab, labRequest, request)
                    .doOnNext(chunk -> {
                    })
                    .doOnComplete(() -> {
                    })
                    .doOnError(error -> {
                        log.error("스트리밍 {} 전략 실행 실패", getSupportedType(), error);
                    });

        } catch (DiagnosisException e) {
            log.error("스트리밍 {} 전략 실행 실패 (DiagnosisException): {}",
                    this.getClass().getSimpleName(), e.getMessage());
            return Flux.error(e);
        } catch (Exception e) {
            log.error("스트리밍 {} 전략 실행 실패 (Exception)",
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
                    labType.getSimpleName() + "은 AILab 인터페이스를 구현하지 않습니다"
            );
        }

        Class<? extends AILab<?, ?>> aiLabType = (Class<? extends AILab<?, ?>>) labType;
        Optional<? extends AILab<?, ?>> labOpt = labFactory.getLab(aiLabType);

        if (labOpt.isEmpty()) {
            throw new DiagnosisException(
                    getSupportedType().name(),
                    "LAB_NOT_FOUND",
                    labType.getSimpleName() + "을 찾을 수 없습니다"
            );
        }

        return labOpt.get();
    }

    protected abstract void validateRequest(AIRequest<T> request) throws DiagnosisException;
    protected abstract Class<?> getLabType();
    protected abstract Object buildLabRequest(AIRequest<T> request) throws DiagnosisException;
    protected abstract R processLabExecution(Object lab, Object labRequest, AIRequest<T> request) throws Exception;
    protected abstract Mono<R> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<T> originRequest);
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<T> request) {
        return Flux.error(new UnsupportedOperationException("스트리밍이 지원되지 않습니다"));
    }
    protected String getExecutionErrorMessage() {
        return getSupportedType().getDisplayName() + " 진단 실행 중 오류 발생: ";
    }
    protected String getAsyncExecutionErrorMessage() {
        return "비동기 " + getSupportedType().getDisplayName() + " 진단 실행 중 오류 발생: ";
    }
    protected String getStreamExecutionErrorMessage() {
        return "스트리밍 " + getSupportedType().getDisplayName() + " 진단 실행 중 오류 발생: ";
    }

    @Override
    public final PipelineConfiguration<T> suggestPipelineConfiguration(AIRequest<T> request) {
        PipelineConfig config = getPipelineConfig();
        PipelineConfiguration.Builder<T> builder = PipelineConfiguration.builder();
        builder.addStep(PipelineStep.PREPROCESSING);
        builder.addStep(PipelineStep.CONTEXT_RETRIEVAL);
        builder.addStep(PipelineStep.PROMPT_GENERATION);
        builder.addStep(PipelineStep.LLM_EXECUTION);
        builder.addStep(PipelineStep.RESPONSE_PARSING);
        builder.addStep(PipelineStep.POSTPROCESSING);
        builder.timeoutSeconds(config.getTimeoutSeconds());
        return builder.build();
    }

    protected PipelineConfig getPipelineConfig() {
        return PipelineConfig.defaultConfig();
    }
}