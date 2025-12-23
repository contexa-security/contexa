package io.contexa.contexacore.std.operations;

import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 분산 전략 실행을 담당하는 전용 서비스
 *
 * 핵심 역할:
 * 1. 마스터 브레인(AINativeIAMOperations)의 지휘를 받아 구체적인 실행 담당
 * 2. DiagnosisStrategyRegistry를 통해 적절한 전략 선택 및 실행
 * 3. AI 파이프라인과 전략 실행의 조율
 * PipelineOrchestrator 직접 사용 (새로운 아키텍처)
 *
 * 자연의 이치:
 * - AINativeIAMOperations -> DistributedStrategyExecutor -> DiagnosisStrategyRegistry -> 구체적 전략
 * - 각 계층은 자신의 역할만 수행하고 하위 계층에 위임
 */
@Slf4j
public class DistributedStrategyExecutor<T extends DomainContext> {

    private final PipelineOrchestrator orchestrator;
    private final RedisEventPublisher eventPublisher;

    // ==================== 핵심 의존성: 전략 레지스트리 ====================
    private final AIStrategyRegistry strategyRegistry; // 실제 전략 실행 담당

    @Autowired
    public DistributedStrategyExecutor(PipelineOrchestrator orchestrator,
                                     RedisEventPublisher eventPublisher,
                                       AIStrategyRegistry strategyRegistry) {
        this.orchestrator = orchestrator;
        this.eventPublisher = eventPublisher;
        this.strategyRegistry = strategyRegistry; // 전략 레지스트리 주입

        log.info("DistributedStrategyExecutor initialized with DiagnosisStrategyRegistry - PipelineOrchestrator 직접 사용");
    }
    
    /**
     * 분산 전략 실행 - 모든 AI 진단의 핵심 엔진
     * 
     * 자연의 이치:
     * - 모든 AI 전략은 이 메서드를 통해 실행됨
     * - DiagnosisStrategyRegistry 에서 적절한 전략 선택
     * - 전략 실행 실패 시 AI 파이프라인 폴백
     * - 분산 환경에서 세션 상태 관리
     */
    public <R extends AIResponse> R executeDistributedStrategy(AIRequest<T> request,
                                                               Class<R> responseType,
                                                               String sessionId,
                                                               String auditId) {
        log.info("Distributed Strategy Executor: Starting strategy execution for session: {}", sessionId);

        try {
            // 1. 전략 레지스트리를 통한 전략 실행 시도
            R result = executeStrategyThroughRegistry(request, responseType, sessionId);

            // 2. 결과 검증
            validateResult(result, sessionId);

            log.info("Distributed Strategy Executor: Strategy execution completed successfully for session: {}", sessionId);
            return result;

        } catch (Exception e) {
            log.warn("Strategy execution failed for session: {}, falling back to AI Pipeline", sessionId, e);

            // 폴백: AI 파이프라인 실행
            R fallbackResult = executeAIPipelineFallback(request, responseType, sessionId);

            return fallbackResult;
        }
    }
    
    /**
     * 완전 비동기 분산 전략 실행 - executeDistributedStrategy의 비동기 버전
     * 
     * 새로운 비동기 진입점:
     * - 모든 처리 과정이 비블로킹
     * - executeStrategyThroughRegistryAsync() 호출
     * - 성능 최적화를 위한 진정한 비동기 처리
     */
    public <R extends AIResponse> Mono<R> executeDistributedStrategyAsync(AIRequest<T> request,
                                                                         Class<R> responseType,
                                                                         String sessionId,
                                                                         String auditId) {
        log.info("Distributed Strategy Executor: Starting ASYNC strategy execution for session: {}", sessionId);

        // 전략 레지스트리를 통한 비동기 전략 실행 시도
        return executeStrategyThroughRegistryAsync(request, responseType, sessionId)
            .doOnSuccess(result -> {
                // 결과 검증
                validateResult(result, sessionId);
                log.info("Distributed Strategy Executor: ASYNC strategy execution completed successfully for session: {}", sessionId);
            })
            .onErrorResume(error -> {
                log.warn("ASYNC strategy execution failed for session: {}, falling back to AI Pipeline", sessionId, error);
                // 폴백: AI 파이프라인 비동기 실행
                return executeAIPipelineFallbackAsync(request, responseType, sessionId);
            });
    }
    
    /**
     * 분산 전략 스트리밍 실행 - 마스터 브레인의 명령을 받아 스트리밍 방식으로 실행
     * 
     * 실행 흐름 (executeDistributedStrategy와 동일한 공정):
     * 1. LAB_ALLOCATION: 세션 상태 업데이트 및 랩 전략 생성
     * 2. EXECUTING: DiagnosisStrategyRegistry를 통한 실제 전략 스트리밍 실행
     * 3. VALIDATING: 실시간 검증 및 세션 상태 업데이트
     * 4. COMPLETED: 스트리밍 완료 처리
     */
    public <R extends AIResponse> Flux<String> executeDistributedStrategyStream(AIRequest<T> request,
                                                                                Class<R> responseType,
                                                                                String sessionId,
                                                                                String auditId) {
        try {
            log.info("Starting streaming strategy execution for session: {}", sessionId);

            // DiagnosisStrategyRegistry를 통한 스트리밍 전략 실행
            return executeStrategyThroughRegistryStream(request, responseType, sessionId)
                .doOnNext(chunk -> {
                    log.debug("Streaming chunk received for session: {} - length: {}", sessionId, chunk.length());
                })
                .doOnComplete(() -> {
                    log.info("Streaming strategy execution completed for session: {}", sessionId);
                })
                .doOnError(error -> {
                    log.error("Streaming strategy execution failed for session: {} - {}", sessionId, error.getMessage());
                });

        } catch (Exception e) {
            log.error("Distributed streaming strategy execution failed for session: {}", sessionId, e);
            return Flux.error(new AIOperationException("Streaming strategy execution failed", e));
        }
    }
    
    /**
     * 핵심 메서드: DiagnosisStrategyRegistry를 통한 전략 실행
     * 
     * 이 메서드가 실제로 DiagnosisStrategyRegistry의 executeStrategy()를 호출합니다.
     */
    private <R extends AIResponse> R executeStrategyThroughRegistry(AIRequest<T> request,
                                                                   Class<R> responseType, 
                                                                   String sessionId) {
        try {
            log.debug("Executing strategy through registry for session: {} - diagnosisType: {}", 
                sessionId, request.getDiagnosisType());
            
            R result = strategyRegistry.executeStrategy(request, responseType);
            
            log.debug("Strategy execution completed for session: {} - resultType: {}", 
                sessionId, result.getClass().getSimpleName());
            
            return result;
            
        } catch (DiagnosisException e) {
            log.error("Strategy registry execution failed for session: {} - {}", sessionId, e.getMessage());
            
            // 폴백: AI 파이프라인 시도
            log.info("Attempting fallback to AI pipeline for session: {}", sessionId);
            return executeAIPipelineFallback(request, responseType, sessionId);
            
        } catch (Exception e) {
            log.error("Unexpected error in strategy execution for session: {}", sessionId, e);
            throw new DiagnosisException(
                request.getDiagnosisType() != null ? request.getDiagnosisType().name() : "UNKNOWN",
                "STRATEGY_EXECUTION_ERROR",
                "전략 실행 중 예상치 못한 오류가 발생했습니다: " + e.getMessage()
            );
        }
    }
    
    /**
     * 핵심 메서드: DiagnosisStrategyRegistry를 통한 스트리밍 전략 실행
     * 
     * 이 메서드가 실제로 DiagnosisStrategyRegistry의 executeStrategy()를 스트리밍 방식으로 호출합니다.
     */
    private <R extends AIResponse> Flux<String> executeStrategyThroughRegistryStream(AIRequest<T> request,
                                                                                    Class<R> responseType, 
                                                                                    String sessionId) {
        try {
            log.debug("Executing streaming strategy through registry for session: {} - diagnosisType: {}", 
                sessionId, request.getDiagnosisType());
            
            // 핵심: DiagnosisStrategyRegistry에서 실제 스트리밍 전략 실행
            log.debug("실시간 스트리밍 전략 실행 시작 for session: {} - diagnosisType: {}", 
                sessionId, request.getDiagnosisType());
            
            return strategyRegistry.executeStrategyStream(request, responseType)
                .doOnNext(chunk -> log.debug("실시간 청크 수신 for session: {} - length: {}", 
                    sessionId, chunk.length()))
                .doOnComplete(() -> log.debug("실시간 스트리밍 전략 실행 완료 for session: {}", sessionId))
                .doOnError(error -> log.error("실시간 스트리밍 전략 실행 실패 for session: {}", sessionId, error));
            
        } catch (DiagnosisException e) {
            log.error("Streaming strategy registry execution failed for session: {} - {}", sessionId, e.getMessage());
            
            // 폴백: AI 파이프라인 스트리밍 시도
            log.info("Attempting fallback to AI pipeline streaming for session: {}", sessionId);
            return executeAIPipelineStreamingFallback(request, responseType, sessionId);
            
        } catch (Exception e) {
            log.error("Unexpected error in streaming strategy execution for session: {}", sessionId, e);
            return Flux.error(new DiagnosisException(
                request.getDiagnosisType() != null ? request.getDiagnosisType().name() : "UNKNOWN",
                "STREAMING_STRATEGY_EXECUTION_ERROR",
                "스트리밍 전략 실행 중 예상치 못한 오류가 발생했습니다: " + e.getMessage()
            ));
        }
    }
    
    /**
     * 폴백: AI 파이프라인 스트리밍 실행 (전략 실행 실패 시)
     */
    private <R extends AIResponse> Flux<String> executeAIPipelineStreamingFallback(AIRequest<T> request,
                                                                                  Class<R> responseType, 
                                                                                  String sessionId) {
        try {
            log.info("Fallback: AI Pipeline streaming execution for session: {}", sessionId);
            
            // 파이프라인 설정 생성
            PipelineConfiguration config = createPipelineConfiguration();
            
            // 파이프라인 스트리밍 실행 (PipelineOrchestrator 사용)
            return orchestrator.executeStream(request, config)
                .ofType(String.class) // String으로 타입 필터링
                .onErrorResume(error -> {
                    log.error("AI Pipeline streaming fallback failed for session: {}", sessionId, error);
                    // 최종 폴백: Mock 스트리밍 응답 사용
                    return createMockStreamingResponse(request, responseType, sessionId);
                });
            
        } catch (Exception e) {
            log.error("AI Pipeline streaming fallback setup failed for session: {}", sessionId, e);
            return createMockStreamingResponse(request, responseType, sessionId);
        }
    }
    
    /**
     * Mock 스트리밍 응답 생성 (최종 폴백) - 범용화
     */
    private <R extends AIResponse> Flux<String> createMockStreamingResponse(AIRequest<T> request,
                                                                           Class<R> responseType, 
                                                                           String sessionId) {
        try {
            // 범용 Mock 응답 생성
            String mockData = String.format("MOCK_STREAMING_RESPONSE_%s_%s", 
                responseType.getSimpleName(), sessionId);
            return Flux.just(mockData);
        } catch (Exception e) {
            log.error("Mock streaming response creation failed for session: {}", sessionId, e);
            return Flux.just("ERROR: Mock streaming response creation failed");
        }
    }
    /**
     * 폴백: AI 파이프라인 실행 (전략 실행 실패 시)
     */
    private <R extends AIResponse> R executeAIPipelineFallback(AIRequest<T> request, Class<R> responseType, String sessionId) {
        try {
            log.info("Fallback: AI Pipeline execution for session: {}", sessionId);
            
            // 파이프라인 설정 생성
            PipelineConfiguration config = createPipelineConfiguration();
            
            // 파이프라인 실행: 안전한 타입 캐스팅 (비동기 → 동기 변환)
            Object rawResult = orchestrator.execute(request, config, responseType).block();
            
            // 타입 안전성 확인 후 캐스팅
            if (rawResult != null && responseType.isInstance(rawResult)) {
                return responseType.cast(rawResult);
            } else {
                log.warn("Pipeline returned unexpected type: {} for expected: {}", 
                    rawResult != null ? rawResult.getClass().getSimpleName() : "null", 
                    responseType.getSimpleName());
                return createMockResponse(request, responseType, sessionId);
            }
            
        } catch (Exception e) {
            log.error("AI Pipeline fallback failed for session: {}", sessionId, e);
            // 최종 폴백: Mock 응답 사용
            return createMockResponse(request, responseType, sessionId);
        }
    }
    
    /**
     * 완전 비동기 분산 전략 실행 - executeDistributedStrategy의 비동기 버전
     * 
     * 새로운 비동기 진입점:
     * - 모든 처리 과정이 비블로킹
     * - DiagnosisStrategyRegistry.executeStrategyAsync() 호출
     * - 성능 최적화를 위한 진정한 비동기 처리
     */
    private <R extends AIResponse> Mono<R> executeStrategyThroughRegistryAsync(AIRequest<T> request,
                                                                              Class<R> responseType, 
                                                                              String sessionId) {
        try {
            log.debug("비동기 전략 실행: {} - session: {}", 
                request.getDiagnosisType(), sessionId);
            
            return strategyRegistry.executeStrategyAsync(request, responseType)
                .doOnSuccess(result -> {
                    log.debug("비동기 전략 실행 성공: {} - session: {}", 
                        result.getClass().getSimpleName(), sessionId);
                })
                .doOnError(error -> {
                    log.error("비동기 전략 실행 실패: session: {} - {}", sessionId, error.getMessage());
                });
            
        } catch (DiagnosisException e) {
            log.error("비동기 전략 실행 실패: session: {} - {}", sessionId, e.getMessage());
            return Mono.error(new AIOperationException("비동기 전략 실행 실패", e));
        }
    }

    /**
     * 폴백: AI 파이프라인 비동기 실행 (전략 실행 실패 시)
     */
    private <R extends AIResponse> Mono<R> executeAIPipelineFallbackAsync(AIRequest<T> request,
                                                                         Class<R> responseType, 
                                                                         String sessionId) {
        return Mono.fromCallable(() -> executeAIPipelineFallback(request, responseType, sessionId));
    }
    
    /**
     * 파이프라인 설정 생성
     */
    private PipelineConfiguration createPipelineConfiguration() {
        return PipelineConfiguration.builder()
            .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
            .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
            .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
            .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
            .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
            .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
            .addParameter("enableCaching", true)
            .addParameter("timeoutSeconds", 300)
            .addParameter("retryCount", 3)
            .timeoutSeconds(300)
            .enableCaching(true)
            .build();
    }
    
    /**
     * Mock 응답 생성 (최종 폴백) - 범용화
     */
    @SuppressWarnings("unchecked")
    private <R extends AIResponse> R createMockResponse(AIRequest<T> request,
                                                        Class<R> responseType,
                                                        String sessionId) {
        // 범용화 임시 처리 - 실제 응답 생성은 상위 레이어에서 처리
        log.warn("Mock response creation not implemented in generic version - session: {}", sessionId);
        throw new AIOperationException("Mock response creation not supported in generic version");
    }
    
    /**
     * 결과 검증
     */
    private void validateResult(AIResponse result, String sessionId) {
        if (result == null) {
            throw new AIOperationException("Strategy execution returned null result for session: " + sessionId);
        }
        
        // 추가 검증 로직
        log.debug("Result validation completed for session: {}", sessionId);
    }
    
} 