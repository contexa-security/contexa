package io.contexa.contexacore.std.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration.PipelineStep;
import io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics;
import io.contexa.contexacore.std.pipeline.condition.AlwaysExecuteCondition;
import io.contexa.contexacore.std.pipeline.condition.ComplexityThresholdCondition;
import io.contexa.contexacore.std.pipeline.condition.ContextRetrievalOptionalCondition;
import io.contexa.contexacore.std.pipeline.condition.FastPathCondition;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;


@Slf4j
public abstract class AbstractAIStrategy<T extends DomainContext, R extends AIResponse> implements AIStrategy<T, R> {

    protected final AILabFactory labFactory;

    protected AbstractAIStrategy(AILabFactory labFactory) {
        this.labFactory = labFactory;
        log.info("{} initialized with AILabFactory", this.getClass().getSimpleName());
    }

    
    @Override
    public R execute(AIRequest<T> request, Class<R> responseType) throws DiagnosisException {
        log.info("{} 전략 실행 시작 - 요청: {}",
                this.getClass().getSimpleName(), request.getRequestId());

        try {
            
            validateRequest(request);

            
            Object lab = getRequiredLab();

            
            Object labRequest = buildLabRequest(request);

            
            R response = processLabExecution(lab, labRequest, request);

            log.info("{} 전략 실행 완료 - 응답: {}",
                    this.getClass().getSimpleName(), getSupportedType());
            return response;

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
        log.info("비동기 {} 전략 실행 시작 - 요청: {}",
                this.getClass().getSimpleName(), request.getRequestId());

        return Mono.fromRunnable(() -> validateRequest(request))
                .then(Mono.fromCallable(this::getRequiredLab))
                .flatMap(lab -> {
                    Object labRequest = buildLabRequest(request);
                    log.info("비동기 {} 요청 처리 시작", getSupportedType());

                    return processLabExecutionAsync(lab, labRequest, request)
                            .doOnSuccess(response -> {
                                log.info("비동기 {} 전략 실행 완료", getSupportedType());
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

        log.info("스트리밍 {} 전략 실행 시작 - 요청: {}",
                this.getClass().getSimpleName(), request.getRequestId());

        try {
            validateRequest(request);
            Object lab = getRequiredLab();
            Object labRequest = buildLabRequest(request);

            return processLabExecutionStream(lab, labRequest, request)
                    .doOnNext(chunk -> {
                        log.debug("스트리밍 청크 수신: {}",
                                chunk.length() > 50 ? chunk.substring(0, 50) + "..." : chunk);
                    })
                    .doOnComplete(() -> {
                        log.info("스트리밍 {} 전략 실행 완료", getSupportedType());
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
    public final PipelineConfiguration<T> suggestPipelineConfiguration(
            AIRequest<T> request,
            RequestCharacteristics characteristics) {

        log.debug("[{}] 파이프라인 구성 제안 시작 - {}", this.getClass().getSimpleName(), characteristics);

        
        PipelineConfig config = getPipelineConfig();
        log.info("[{}] PipelineConfig 사용 - ContextRetrieval: {}, PostProcessing: {}",
                this.getClass().getSimpleName(),
                config.getContextRetrieval(),
                config.getPostProcessing());

        
        PipelineConfiguration.Builder<T> builder = PipelineConfiguration.builder();

        
        builder.addConditionalStep(PipelineStep.PREPROCESSING, new AlwaysExecuteCondition<>());

        
        addContextRetrievalStep(builder, config.getContextRetrieval(), characteristics);

        
        builder.addConditionalStep(PipelineStep.PROMPT_GENERATION, new AlwaysExecuteCondition<>());

        
        builder.addConditionalStep(PipelineStep.LLM_EXECUTION, new AlwaysExecuteCondition<>());

        
        builder.addConditionalStep(PipelineStep.RESPONSE_PARSING, new AlwaysExecuteCondition<>());

        
        addPostProcessingStep(builder, config.getPostProcessing(), characteristics);

        
        builder.timeoutSeconds(config.getTimeoutSeconds());

        PipelineConfiguration<T> configuration = builder.build();

        log.info("[{}] 최종 파이프라인 구성 완료 - Description: {}",
                this.getClass().getSimpleName(),
                config.getDescription());

        return configuration;
    }

    
    private void addContextRetrievalStep(
            PipelineConfiguration.Builder<T> builder,
            PipelineConfig.ContextRetrievalStrategy strategy,
            RequestCharacteristics characteristics) {

        switch (strategy) {
            case ALWAYS_REQUIRED:
                
                builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new AlwaysExecuteCondition<>());
                log.debug("Context Retrieval: ALWAYS_REQUIRED");
                break;

            case DYNAMIC:
                
                if (characteristics.isRequiresContextRetrieval()) {
                    builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new AlwaysExecuteCondition<>());
                    log.debug("Context Retrieval: DYNAMIC → Required (복잡도 높음)");
                } else {
                    builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new ContextRetrievalOptionalCondition<>());
                    log.debug("Context Retrieval: DYNAMIC → Optional (복잡도 낮음)");
                }
                break;

            case OPTIONAL:
                
                builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new ContextRetrievalOptionalCondition<>());
                log.debug("Context Retrieval: OPTIONAL");
                break;
        }
    }

    
    private void addPostProcessingStep(
            PipelineConfiguration.Builder<T> builder,
            PipelineConfig.PostProcessingStrategy strategy,
            RequestCharacteristics characteristics) {

        switch (strategy) {
            case ALWAYS:
                
                builder.addConditionalStep(PipelineStep.POSTPROCESSING, new AlwaysExecuteCondition<>());
                log.debug("Post Processing: ALWAYS");
                break;

            case DYNAMIC:
                
                if (characteristics.isRequiresHighAccuracy()) {
                    builder.addConditionalStep(PipelineStep.POSTPROCESSING, new AlwaysExecuteCondition<>());
                    log.debug("Post Processing: DYNAMIC → Required (정확도 중요)");
                } else {
                    builder.addConditionalStep(PipelineStep.POSTPROCESSING, new FastPathCondition<>());
                    log.debug("Post Processing: DYNAMIC → FastPath (빠른 응답)");
                }
                break;

            case FAST_PATH:
                
                builder.addConditionalStep(PipelineStep.POSTPROCESSING, new FastPathCondition<>());
                log.debug("Post Processing: FAST_PATH");
                break;
        }
    }

    
    protected PipelineConfig getPipelineConfig() {
        return PipelineConfig.defaultConfig();
    }
}