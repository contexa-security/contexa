package io.contexa.contexacore.std.pipeline;

import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.pipeline.analyzer.RequestAnalyzer;
import io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import io.contexa.contexacore.std.strategy.AIStrategy;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.domain.SessionState;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.Map;

/**
 * 파이프라인 조율자 (Orchestrator)
 * 
 * SRP: 실행자 선택 및 조율만 담당
 * OCP: 새로운 PipelineExecutor 추가 시 자동 감지
 * 
 * 역할:
 * - 요청에 맞는 최적의 PipelineExecutor 선택
 * - 우선순위 기반 실행자 결정
 * - 실행 결과 통합 관리
 * - 에러 처리 및 Fallback
 * 
 * 선택 우선순위:
 * 1. 도메인 특화 Executor (IAM, Finance 등)
 * 2. 범용 Universal Executor
 */
@Slf4j
@Component
public class PipelineOrchestrator {

    private final List<PipelineExecutor> executors;
    private final RequestAnalyzer requestAnalyzer;
    private final Map<DiagnosisType, AIStrategy<?, ?>> strategyMap;

    @Autowired
    public PipelineOrchestrator(List<PipelineExecutor> executors,
                                RequestAnalyzer requestAnalyzer,
                                List<AIStrategy<?, ?>> strategies) {
        this.executors = executors.stream()
                .sorted((a, b) -> Integer.compare(a.getPriority(), b.getPriority()))
                .toList();
        this.requestAnalyzer = requestAnalyzer;

        // Strategy 맵 구성
        this.strategyMap = new java.util.concurrent.ConcurrentHashMap<>();
        for (AIStrategy<?, ?> strategy : strategies) {
            strategyMap.put(strategy.getSupportedType(), strategy);
        }

        log.info("PipelineOrchestrator 초기화: {} 실행자, {} 전략 등록", executors.size(), strategies.size());
        for (PipelineExecutor executor : this.executors) {
            log.info("   - {}: {} (우선순위: {})",
                    executor.getSupportedDomain(),
                    executor.getClass().getSimpleName(),
                    executor.getPriority());
        }
    }
    
    /**
     * 완전한 파이프라인 실행 (6단계) - config 없이 호출 가능
     */
    public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            Class<R> responseType) {
        return execute(request, null, responseType);
    }

    /**
     * 완전한 파이프라인 실행 (6단계) - 하위 호환성 유지
     */
    public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            Class<R> responseType) {

        log.info("[Orchestrator] Pipeline 실행 요청: {} (타입: {})",
                request.getRequestId(), responseType.getSimpleName());

        // 동적 파이프라인 재구성
        return Mono.fromCallable(() -> {
                    // 1. 요청 특성 분석
                    RequestCharacteristics characteristics = requestAnalyzer.analyze(request);

                    // 2. AIStrategy 조회
                    AIStrategy<T, R> strategy = getStrategyForRequest(request);

                    // 3. 최적화된 파이프라인 구성 제안
                    PipelineConfiguration<T> optimizedConfig = null;
                    if (strategy != null) {
                        optimizedConfig = strategy.suggestPipelineConfiguration(request, characteristics);
                    }

                    // 4. 제안된 구성 사용 우선순위: optimizedConfig > configuration > default
                    PipelineConfiguration<T> finalConfig;
                    if (optimizedConfig != null) {
                        finalConfig = optimizedConfig;
                        log.info("[Orchestrator] Strategy 최적화 파이프라인 사용");
                    } else if (configuration != null) {
                        finalConfig = configuration;
                        log.info("[Orchestrator] 전달받은 파이프라인 사용");
                    } else {
                        finalConfig = createDefaultPipelineConfiguration();
                        log.info("[Orchestrator] 기본 파이프라인 사용");
                    }

                    // 5. 요청 특성을 파이프라인 컨텍스트에 저장 (조건 평가용)
                    Map<String, Object> characteristicsMap = characteristics.toContextMap();
                    for (Map.Entry<String, Object> entry : characteristicsMap.entrySet()) {
                        finalConfig.getParameters().put(entry.getKey(), entry.getValue());
                    }

                    log.info("[Orchestrator] 요청 분석 완료 - {}", characteristics);
                    log.info("[Orchestrator] 파이프라인 단계: {}, 조건부 단계: {}",
                            finalConfig.getSteps().size(),
                            finalConfig.getStepConditions().size());

                    return finalConfig;
                })
                .flatMap(finalConfig -> selectExecutor(request, finalConfig)
                        .map(executor -> {
                            log.info("[Orchestrator] 실행자 선택: {} - {}",
                                    executor.getSupportedDomain(), executor.getClass().getSimpleName());
                            return executor;
                        })
                        .flatMap(executor -> executor.execute(request, finalConfig, responseType))
                )
                .doOnSuccess(response ->
                        log.info("[Orchestrator] Pipeline 완료: {}", request.getRequestId()))
                .doOnError(error ->
                        log.error("[Orchestrator] Pipeline 실패: {} - {}",
                                request.getRequestId(), error.getMessage(), error))
                .onErrorResume(error -> createFallbackResponse(request, responseType, error));
    }

    /**
     * 요청에 맞는 AIStrategy 조회
     */
    private <T extends DomainContext, R extends AIResponse> AIStrategy<T, R> getStrategyForRequest(
            AIRequest<T> request) {
        DiagnosisType type = request.getDiagnosisType();
        if (type == null) {
            return null;
        }
        return (AIStrategy<T, R>) strategyMap.get(type);
    }
    
    /**
     * 스트리밍 파이프라인 실행 - config 없이 호출 가능
     */
    public <T extends DomainContext> Flux<String> executeStream(AIRequest<T> request) {
        return executeStream(request, null);
    }

    /**
     * 스트리밍 파이프라인 실행 - 하위 호환성 유지
     */
    public <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration) {

        log.info("[Orchestrator] 스트리밍 Pipeline 실행 요청: {}", request.getRequestId());

        // config가 없으면 Strategy의 제안 사용
        if (configuration == null) {
            RequestCharacteristics characteristics = requestAnalyzer.analyze(request);
            AIStrategy<T, ?> strategy = getStrategyForRequest(request);

            if (strategy != null) {
                PipelineConfiguration<T> optimizedConfig = strategy.suggestPipelineConfiguration(request, characteristics);
                if (optimizedConfig != null) {
                    // 스트리밍 활성화된 새 구성 생성
                    configuration = PipelineConfiguration.<T>builder()
                            .steps(optimizedConfig.getSteps())
                            .stepConditions(optimizedConfig.getStepConditions())
                            .customSteps(optimizedConfig.getCustomSteps())
                            .timeoutSeconds(optimizedConfig.getTimeoutSeconds())
                            .enableStreaming(true)
                            .build();
                    log.info("[Orchestrator] Strategy 최적화 스트리밍 파이프라인 사용");
                }
            }

            if (configuration == null) {
                configuration = createDefaultStreamingPipelineConfiguration();
                log.info("[Orchestrator] 기본 스트리밍 파이프라인 사용");
            }
        }

        PipelineConfiguration<T> finalConfig = configuration;

        return selectExecutor(request, finalConfig)
                .map(executor -> {
                    log.info("[Orchestrator] 스트리밍 실행자 선택: {} - {}",
                            executor.getSupportedDomain(), executor.getClass().getSimpleName());
                    return executor;
                })
                .flatMapMany(executor -> executor.executeStream(request, finalConfig))
                .doOnComplete(() ->
                    log.info("[Orchestrator] 스트리밍 완료: {}", request.getRequestId()))
                .doOnError(error ->
                    log.error("[Orchestrator] 스트리밍 실패: {} - {}",
                              request.getRequestId(), error.getMessage(), error))
                .onErrorResume(error -> Flux.just("ERROR: " + error.getMessage()));
    }
    
    /**
     * 요청에 맞는 최적의 실행자 선택
     * 
     * 선택 로직:
     * 1. 도메인별 특화 실행자 우선 (낮은 우선순위 값)
     * 2. 설정 지원 여부 확인
     * 3. 범용 실행자로 Fallback
     */
    private <T extends DomainContext> Mono<PipelineExecutor> selectExecutor(
            AIRequest<T> request, 
            PipelineConfiguration<T> configuration) {
        
        // 도메인 힌트 추출 (Context 타입 또는 Request 타입 기반)
        String domainHint = extractDomainHint(request);
        log.debug("[Orchestrator] 도메인 힌트: {}", domainHint);
        
        // 우선순위 기반으로 적합한 실행자 찾기
        Optional<PipelineExecutor> selectedExecutor = executors.stream()
                .filter(executor -> executor.supportsConfiguration(configuration))
                .filter(executor -> isDomainMatch(executor, domainHint))
                .findFirst();
        
        if (selectedExecutor.isPresent()) {
            return Mono.just(selectedExecutor.get());
        }
        
        Optional<PipelineExecutor> fallbackExecutor = executors.stream()
                .filter(executor -> executor.supportsConfiguration(configuration))
                .findFirst();
        
        if (fallbackExecutor.isPresent()) {
            log.warn("[Orchestrator] 도메인 매칭 실패, Fallback 실행자 사용: {}", 
                    fallbackExecutor.get().getSupportedDomain());
            return Mono.just(fallbackExecutor.get());
        }
        
        return Mono.error(new IllegalStateException(
            "설정을 지원하는 PipelineExecutor를 찾을 수 없습니다: " + configuration.getSteps()));
    }
    
    /**
     * 요청에서 도메인 힌트 추출
     */
    private <T extends DomainContext> String extractDomainHint(AIRequest<T> request) {
        // 1. Context 타입 기반 추출
        String contextTypeName = request.getContext().getClass().getSimpleName();
        if (contextTypeName.toLowerCase().contains("iam")) {
            return "IAM";
        }
        
        // 2. Request 타입 기반 추출  
        String requestTypeName = request.getClass().getSimpleName();
        if (requestTypeName.toLowerCase().contains("iam")) {
            return "IAM";
        }
        
        // 3. 패키지명 기반 추출
        String operation = request.getPromptTemplate();
        if (operation.contains("Streaming")) {
            return "STREAMING-UNIVERSAL";
        }
        
        return "UNIVERSAL";
    }
    
    /**
     * 실행자와 도메인 매칭 여부 확인
     */
    private boolean isDomainMatch(PipelineExecutor executor, String domainHint) {
        String executorDomain = executor.getSupportedDomain();
        
        if (executorDomain.equalsIgnoreCase(domainHint)) {
            return true;
        }

        return "UNIVERSAL".equalsIgnoreCase(executorDomain);
    }
    
    /**
     * Fallback 응답 생성
     */
    @SuppressWarnings("unchecked")
    private <T extends DomainContext, R extends AIResponse> Mono<R> createFallbackResponse(
            AIRequest<T> request,
            Class<R> responseType,
            Throwable error) {

        log.error("[Orchestrator] Pipeline 실행 실패, Fallback 응답 생성: {} - {}",
                 request.getRequestId(), error.getMessage(), error);

        try {
            R response;

            // SoarResponse 타입인 경우 특별 처리
            if (responseType.equals(SoarResponse.class)) {
                SoarResponse soarResponse = new SoarResponse(
                    request.getRequestId(),
                    AIResponse.ExecutionStatus.FAILURE
                );

                // 에러 정보 설정
                soarResponse.withError("Pipeline execution failed: " + error.getMessage())
                    .withConfidenceScore(0.0)
                    .withMetadata("errorType", error.getClass().getSimpleName())
                    .withMetadata("timestamp", System.currentTimeMillis());

                // SOAR 특화 필드 설정
                soarResponse.setAnalysisResult("Failed to complete SOAR analysis due to pipeline error: " + error.getMessage());
                soarResponse.setSummary("Pipeline execution failed");
                soarResponse.setRecommendations(List.of(
                    "Review pipeline configuration",
                    "Check model availability and API keys",
                    "Verify context retrieval settings",
                    "Retry the operation"
                ));
                soarResponse.setSessionState(SessionState.ERROR);
                soarResponse.setExecutedTools(List.of());

                response = (R) soarResponse;
                log.info("[Orchestrator] SoarResponse fallback 응답 생성 완료");
            } else {
                // 다른 AIResponse 타입들을 위한 일반적인 처리
                try {
                    // 기본 생성자를 사용하여 인스턴스 생성
                    response = responseType.getDeclaredConstructor().newInstance();
                    response.withError("Pipeline execution failed: " + error.getMessage())
                        .withConfidenceScore(0.0)
                        .withMetadata("errorType", error.getClass().getSimpleName());
                    log.info("[Orchestrator] {} fallback 응답 생성 완료", responseType.getSimpleName());
                } catch (NoSuchMethodException e) {
                    // 기본 생성자가 없는 경우, 파라미터가 있는 생성자 시도
                    try {
                        response = responseType.getDeclaredConstructor(String.class, AIResponse.ExecutionStatus.class)
                            .newInstance(request.getRequestId(), AIResponse.ExecutionStatus.FAILURE);
                        response.withError("Pipeline execution failed: " + error.getMessage());
                        log.info("[Orchestrator] {} fallback 응답 생성 완료 (파라미터 생성자 사용)", responseType.getSimpleName());
                    } catch (Exception ex) {
                        log.error("[Orchestrator] Fallback 응답 생성 실패 - 적절한 생성자를 찾을 수 없음", ex);
                        return Mono.error(new RuntimeException(
                            "Failed to create fallback response - no suitable constructor found for " + responseType.getSimpleName(), ex));
                    }
                }
            }

            log.debug("[Orchestrator] Fallback 응답 반환: requestId={}, status=FAILURE", request.getRequestId());
            return Mono.just(response);

        } catch (Exception e) {
            log.error("[Orchestrator] Fallback 응답 생성 중 예외 발생", e);
            return Mono.error(new RuntimeException(
                "Failed to create fallback response for " + responseType.getSimpleName() + ": " + e.getMessage(), e));
        }
    }
    
    /**
     * 등록된 실행자 목록 조회
     */
    public List<String> getRegisteredExecutors() {
        return executors.stream()
                .map(executor -> String.format("%s (%s, 우선순위: %d)",
                        executor.getSupportedDomain(),
                        executor.getClass().getSimpleName(),
                        executor.getPriority()))
                .toList();
    }

    /**
     * 기본 파이프라인 구성 생성
     */
    private <T extends DomainContext> PipelineConfiguration<T> createDefaultPipelineConfiguration() {
        return (PipelineConfiguration<T>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .build();
    }

    /**
     * 기본 스트리밍 파이프라인 구성 생성
     */
    @SuppressWarnings("unchecked")
    private <T extends DomainContext> PipelineConfiguration<T> createDefaultStreamingPipelineConfiguration() {
        return (PipelineConfiguration<T>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .timeoutSeconds(300)
                .enableStreaming(true)
                .build();
    }
} 