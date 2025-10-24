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

/**
 * AI 전략 추상 클래스
 *
 * 모든 AI 전략의 공통 로직을 포함하는 Template Method Pattern 구현
 * 기존 Strategy들의 중복 코드를 추출하여 재사용성 향상
 *
 * @param <T> DomainContext 타입
 * @param <R> AIResponse 타입
 */
@Slf4j
public abstract class AbstractAIStrategy<T extends DomainContext, R extends AIResponse> implements AIStrategy<T, R> {

    protected final AILabFactory labFactory;

    protected AbstractAIStrategy(AILabFactory labFactory) {
        this.labFactory = labFactory;
        log.info("{} initialized with AILabFactory", this.getClass().getSimpleName());
    }

    /**
     * Template Method: 동기 실행
     * 기존 각 Strategy의 execute() 메서드의 공통 패턴을 추출
     */
    @Override
    public R execute(AIRequest<T> request, Class<R> responseType) throws DiagnosisException {
        log.info("{} 전략 실행 시작 - 요청: {}",
                this.getClass().getSimpleName(), request.getRequestId());

        try {
            // 1. 요청 검증 (하위 클래스에서 구현)
            validateRequest(request);

            // 2. Lab 조회 (공통 로직)
            Object lab = getRequiredLab();

            // 3. Lab 요청 생성 (하위 클래스에서 구현)
            Object labRequest = buildLabRequest(request);

            // 4. Lab 실행 및 결과 처리 (하위 클래스에서 구현)
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

    /**
     * Template Method: 비동기 실행
     * 기존 각 Strategy의 executeAsync() 메서드의 공통 패턴을 추출
     */
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

    /**
     * Template Method: 스트리밍 실행
     * 기존 StreamingDiagnosisStrategy의 executeStream() 메서드 패턴을 추출
     */
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

    /**
     * Lab 조회 헬퍼 메서드 (공통 로직)
     */
    protected Object getRequiredLab() throws DiagnosisException {
        Class<?> labType = getLabType();

        // 타입 체크 후 캐스팅
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

    /**
     * 요청 검증 로직 (각 Strategy 별로 다름)
     */
    protected abstract void validateRequest(AIRequest<T> request) throws DiagnosisException;

    /**
     * Lab 타입 반환 (각 Strategy가 사용하는 Lab)
     */
    protected abstract Class<?> getLabType();

    /**
     * Lab 요청 객체 생성 (각 Strategy 별로 다름)
     */
    protected abstract Object buildLabRequest(AIRequest<T> request) throws DiagnosisException;

    /**
     * Lab 실행 및 결과 처리 (동기)
     */
    protected abstract R processLabExecution(Object lab, Object labRequest, AIRequest<T> request) throws Exception;

    /**
     * Lab 실행 및 결과 처리 (비동기)
     */
    protected abstract Mono<R> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<T> originRequest);

    /**
     * Lab 실행 및 결과 처리 (스트리밍)
     * 스트리밍을 지원하는 Strategy만 구현
     */
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

    /**
     * 동적 파이프라인: PipelineConfig와 RequestCharacteristics를 조합하여 최적 파이프라인 생성
     *
     * 하위 클래스는 getPipelineConfig()를 오버라이드하여 도메인별 설정을 제공합니다.
     * AbstractAIStrategy는 이 설정과 요청 특성을 조합하여 최종 파이프라인을 동적으로 구성합니다.
     */
    @Override
    public final PipelineConfiguration<T> suggestPipelineConfiguration(
            AIRequest<T> request,
            RequestCharacteristics characteristics) {

        log.debug("[{}] 파이프라인 구성 제안 시작 - {}", this.getClass().getSimpleName(), characteristics);

        // 1. 하위 클래스로부터 도메인별 설정 가져오기
        PipelineConfig config = getPipelineConfig();
        log.info("[{}] PipelineConfig 사용 - ContextRetrieval: {}, PostProcessing: {}",
                this.getClass().getSimpleName(),
                config.getContextRetrieval(),
                config.getPostProcessing());

        // 2. 설정과 요청 특성을 조합하여 최적 파이프라인 구성
        PipelineConfiguration.Builder<T> builder = PipelineConfiguration.builder();

        // 전처리 (항상 실행)
        builder.addConditionalStep(PipelineStep.PREPROCESSING, new AlwaysExecuteCondition<>());

        // 컨텍스트 검색 (설정 + 요청 특성 기반 동적 결정)
        addContextRetrievalStep(builder, config.getContextRetrieval(), characteristics);

        // 프롬프트 생성 (항상 실행)
        builder.addConditionalStep(PipelineStep.PROMPT_GENERATION, new AlwaysExecuteCondition<>());

        // LLM 실행 (항상 실행)
        builder.addConditionalStep(PipelineStep.LLM_EXECUTION, new AlwaysExecuteCondition<>());

        // 응답 파싱 (항상 실행)
        builder.addConditionalStep(PipelineStep.RESPONSE_PARSING, new AlwaysExecuteCondition<>());

        // 후처리 (설정 + 요청 특성 기반 동적 결정)
        addPostProcessingStep(builder, config.getPostProcessing(), characteristics);

        // 타임아웃 설정
        builder.timeoutSeconds(config.getTimeoutSeconds());

        PipelineConfiguration<T> configuration = builder.build();

        log.info("[{}] 최종 파이프라인 구성 완료 - Description: {}",
                this.getClass().getSimpleName(),
                config.getDescription());

        return configuration;
    }

    /**
     * 컨텍스트 조회 단계 추가 (설정 + 요청 특성 기반 동적 결정)
     */
    private void addContextRetrievalStep(
            PipelineConfiguration.Builder<T> builder,
            PipelineConfig.ContextRetrievalStrategy strategy,
            RequestCharacteristics characteristics) {

        switch (strategy) {
            case ALWAYS_REQUIRED:
                // 항상 컨텍스트 조회 필요
                builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new AlwaysExecuteCondition<>());
                log.debug("Context Retrieval: ALWAYS_REQUIRED");
                break;

            case DYNAMIC:
                // 요청 특성에 따라 동적 결정
                if (characteristics.isRequiresContextRetrieval()) {
                    builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new AlwaysExecuteCondition<>());
                    log.debug("Context Retrieval: DYNAMIC → Required (복잡도 높음)");
                } else {
                    builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new ContextRetrievalOptionalCondition<>());
                    log.debug("Context Retrieval: DYNAMIC → Optional (복잡도 낮음)");
                }
                break;

            case OPTIONAL:
                // 선택적 컨텍스트 조회
                builder.addConditionalStep(PipelineStep.CONTEXT_RETRIEVAL, new ContextRetrievalOptionalCondition<>());
                log.debug("Context Retrieval: OPTIONAL");
                break;
        }
    }

    /**
     * 후처리 단계 추가 (설정 + 요청 특성 기반 동적 결정)
     */
    private void addPostProcessingStep(
            PipelineConfiguration.Builder<T> builder,
            PipelineConfig.PostProcessingStrategy strategy,
            RequestCharacteristics characteristics) {

        switch (strategy) {
            case ALWAYS:
                // 항상 후처리 실행
                builder.addConditionalStep(PipelineStep.POSTPROCESSING, new AlwaysExecuteCondition<>());
                log.debug("Post Processing: ALWAYS");
                break;

            case DYNAMIC:
                // 요청 특성에 따라 동적 결정
                if (characteristics.isRequiresHighAccuracy()) {
                    builder.addConditionalStep(PipelineStep.POSTPROCESSING, new AlwaysExecuteCondition<>());
                    log.debug("Post Processing: DYNAMIC → Required (정확도 중요)");
                } else {
                    builder.addConditionalStep(PipelineStep.POSTPROCESSING, new FastPathCondition<>());
                    log.debug("Post Processing: DYNAMIC → FastPath (빠른 응답)");
                }
                break;

            case FAST_PATH:
                // 빠른 응답을 위해 후처리 생략 가능
                builder.addConditionalStep(PipelineStep.POSTPROCESSING, new FastPathCondition<>());
                log.debug("Post Processing: FAST_PATH");
                break;
        }
    }

    /**
     * 도메인별 파이프라인 설정 제공 (Hook Method)
     *
     * 하위 클래스가 오버라이드하여 도메인 특성에 맞는 PipelineConfig를 반환합니다.
     * 기본값은 PipelineConfig.defaultConfig()입니다.
     *
     * @return 도메인별 파이프라인 설정
     */
    protected PipelineConfig getPipelineConfig() {
        return PipelineConfig.defaultConfig();
    }
}