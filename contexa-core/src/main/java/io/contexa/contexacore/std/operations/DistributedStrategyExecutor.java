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


@Slf4j
public class DistributedStrategyExecutor<T extends DomainContext> {

    private final PipelineOrchestrator orchestrator;
    private final RedisEventPublisher eventPublisher;

    
    private final AIStrategyRegistry strategyRegistry; 

    @Autowired
    public DistributedStrategyExecutor(PipelineOrchestrator orchestrator,
                                     RedisEventPublisher eventPublisher,
                                       AIStrategyRegistry strategyRegistry) {
        this.orchestrator = orchestrator;
        this.eventPublisher = eventPublisher;
        this.strategyRegistry = strategyRegistry; 

        log.info("DistributedStrategyExecutor initialized with DiagnosisStrategyRegistry - PipelineOrchestrator 직접 사용");
    }
    
    
    public <R extends AIResponse> R executeDistributedStrategy(AIRequest<T> request,
                                                               Class<R> responseType,
                                                               String sessionId,
                                                               String auditId) {
        log.info("Distributed Strategy Executor: Starting strategy execution for session: {}", sessionId);

        try {
            
            R result = executeStrategyThroughRegistry(request, responseType, sessionId);

            
            validateResult(result, sessionId);

            log.info("Distributed Strategy Executor: Strategy execution completed successfully for session: {}", sessionId);
            return result;

        } catch (Exception e) {
            log.warn("Strategy execution failed for session: {}, falling back to AI Pipeline", sessionId, e);

            
            R fallbackResult = executeAIPipelineFallback(request, responseType, sessionId);

            return fallbackResult;
        }
    }
    
    
    public <R extends AIResponse> Mono<R> executeDistributedStrategyAsync(AIRequest<T> request,
                                                                         Class<R> responseType,
                                                                         String sessionId,
                                                                         String auditId) {
        log.info("Distributed Strategy Executor: Starting ASYNC strategy execution for session: {}", sessionId);

        
        return executeStrategyThroughRegistryAsync(request, responseType, sessionId)
            .doOnSuccess(result -> {
                
                validateResult(result, sessionId);
                log.info("Distributed Strategy Executor: ASYNC strategy execution completed successfully for session: {}", sessionId);
            })
            .onErrorResume(error -> {
                log.warn("ASYNC strategy execution failed for session: {}, falling back to AI Pipeline", sessionId, error);
                
                return executeAIPipelineFallbackAsync(request, responseType, sessionId);
            });
    }
    
    
    public <R extends AIResponse> Flux<String> executeDistributedStrategyStream(AIRequest<T> request,
                                                                                Class<R> responseType,
                                                                                String sessionId,
                                                                                String auditId) {
        try {
            log.info("Starting streaming strategy execution for session: {}", sessionId);

            
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
    
    
    private <R extends AIResponse> Flux<String> executeStrategyThroughRegistryStream(AIRequest<T> request,
                                                                                    Class<R> responseType, 
                                                                                    String sessionId) {
        try {
            log.debug("Executing streaming strategy through registry for session: {} - diagnosisType: {}", 
                sessionId, request.getDiagnosisType());
            
            
            log.debug("실시간 스트리밍 전략 실행 시작 for session: {} - diagnosisType: {}", 
                sessionId, request.getDiagnosisType());
            
            return strategyRegistry.executeStrategyStream(request, responseType)
                .doOnNext(chunk -> log.debug("실시간 청크 수신 for session: {} - length: {}", 
                    sessionId, chunk.length()))
                .doOnComplete(() -> log.debug("실시간 스트리밍 전략 실행 완료 for session: {}", sessionId))
                .doOnError(error -> log.error("실시간 스트리밍 전략 실행 실패 for session: {}", sessionId, error));
            
        } catch (DiagnosisException e) {
            log.error("Streaming strategy registry execution failed for session: {} - {}", sessionId, e.getMessage());
            
            
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
    
    
    private <R extends AIResponse> Flux<String> executeAIPipelineStreamingFallback(AIRequest<T> request,
                                                                                  Class<R> responseType, 
                                                                                  String sessionId) {
        try {
            log.info("Fallback: AI Pipeline streaming execution for session: {}", sessionId);
            
            
            PipelineConfiguration config = createPipelineConfiguration();
            
            
            return orchestrator.executeStream(request, config)
                .ofType(String.class) 
                .onErrorResume(error -> {
                    log.error("AI Pipeline streaming fallback failed for session: {}", sessionId, error);
                    
                    return createMockStreamingResponse(request, responseType, sessionId);
                });
            
        } catch (Exception e) {
            log.error("AI Pipeline streaming fallback setup failed for session: {}", sessionId, e);
            return createMockStreamingResponse(request, responseType, sessionId);
        }
    }
    
    
    private <R extends AIResponse> Flux<String> createMockStreamingResponse(AIRequest<T> request,
                                                                           Class<R> responseType, 
                                                                           String sessionId) {
        try {
            
            String mockData = String.format("MOCK_STREAMING_RESPONSE_%s_%s", 
                responseType.getSimpleName(), sessionId);
            return Flux.just(mockData);
        } catch (Exception e) {
            log.error("Mock streaming response creation failed for session: {}", sessionId, e);
            return Flux.just("ERROR: Mock streaming response creation failed");
        }
    }
    
    private <R extends AIResponse> R executeAIPipelineFallback(AIRequest<T> request, Class<R> responseType, String sessionId) {
        try {
            log.info("Fallback: AI Pipeline execution for session: {}", sessionId);
            
            
            PipelineConfiguration config = createPipelineConfiguration();
            
            
            Object rawResult = orchestrator.execute(request, config, responseType).block();
            
            
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
            
            return createMockResponse(request, responseType, sessionId);
        }
    }
    
    
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

    
    private <R extends AIResponse> Mono<R> executeAIPipelineFallbackAsync(AIRequest<T> request,
                                                                         Class<R> responseType, 
                                                                         String sessionId) {
        return Mono.fromCallable(() -> executeAIPipelineFallback(request, responseType, sessionId));
    }
    
    
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
    
    
    @SuppressWarnings("unchecked")
    private <R extends AIResponse> R createMockResponse(AIRequest<T> request,
                                                        Class<R> responseType,
                                                        String sessionId) {
        
        log.warn("Mock response creation not implemented in generic version - session: {}", sessionId);
        throw new AIOperationException("Mock response creation not supported in generic version");
    }
    
    
    private void validateResult(AIResponse result, String sessionId) {
        if (result == null) {
            throw new AIOperationException("Strategy execution returned null result for session: " + sessionId);
        }
        
        
        log.debug("Result validation completed for session: {}", sessionId);
    }
    
} 