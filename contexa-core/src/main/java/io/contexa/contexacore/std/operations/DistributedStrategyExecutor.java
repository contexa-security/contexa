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

    private final AIStrategyRegistry strategyRegistry;

    @Autowired
    public DistributedStrategyExecutor(PipelineOrchestrator orchestrator,
                                       RedisEventPublisher eventPublisher,
                                       AIStrategyRegistry strategyRegistry) {
        this.orchestrator = orchestrator;
        this.strategyRegistry = strategyRegistry;

    }

    public <R extends AIResponse> R executeDistributedStrategy(AIRequest<T> request,
                                                               Class<R> responseType,
                                                               String sessionId,
                                                               String auditId) {

        try {

            R result = executeStrategyThroughRegistry(request, responseType, sessionId);

            validateResult(result, sessionId);

            return result;

        } catch (Exception e) {
            log.error("Strategy execution failed for session: {}, falling back to AI Pipeline", sessionId, e);

            return executeAIPipelineFallback(request, responseType, sessionId);
        }
    }

    public <R extends AIResponse> Mono<R> executeDistributedStrategyAsync(AIRequest<T> request,
                                                                          Class<R> responseType,
                                                                          String sessionId,
                                                                          String auditId) {

        return executeStrategyThroughRegistryAsync(request, responseType, sessionId)
                .doOnSuccess(result -> {

                    validateResult(result, sessionId);
                })
                .onErrorResume(error -> {
                    log.error("ASYNC strategy execution failed for session: {}, falling back to AI Pipeline", sessionId, error);

                    return executeAIPipelineFallbackAsync(request, responseType, sessionId);
                });
    }

    public <R extends AIResponse> Flux<String> executeDistributedStrategyStream(AIRequest<T> request,
                                                                                Class<R> responseType,
                                                                                String sessionId,
                                                                                String auditId) {
        try {

            return executeStrategyThroughRegistryStream(request, responseType, sessionId)
                    .doOnNext(chunk -> {
                    })
                    .doOnComplete(() -> {
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

            return strategyRegistry.executeStrategy(request, responseType);

        } catch (DiagnosisException e) {
            log.error("Strategy registry execution failed for session: {} - {}", sessionId, e.getMessage());

            return executeAIPipelineFallback(request, responseType, sessionId);

        } catch (Exception e) {
            log.error("Unexpected error in strategy execution for session: {}", sessionId, e);
            throw new DiagnosisException(
                    request.getDiagnosisType() != null ? request.getDiagnosisType().name() : "UNKNOWN",
                    "STRATEGY_EXECUTION_ERROR",
                    "Unexpected error during strategy execution: " + e.getMessage()
            );
        }
    }

    private <R extends AIResponse> Flux<String> executeStrategyThroughRegistryStream(AIRequest<T> request,
                                                                                     Class<R> responseType,
                                                                                     String sessionId) {
        try {

            return strategyRegistry.executeStrategyStream(request, responseType)
                    .doOnError(error -> log.error("Real-time streaming strategy execution failed for session: {}", sessionId, error));

        } catch (DiagnosisException e) {
            log.error("Streaming strategy registry execution failed for session: {} - {}", sessionId, e.getMessage());

            return executeAIPipelineStreamingFallback(request, responseType, sessionId);

        } catch (Exception e) {
            log.error("Unexpected error in streaming strategy execution for session: {}", sessionId, e);
            return Flux.error(new DiagnosisException(
                    request.getDiagnosisType() != null ? request.getDiagnosisType().name() : "UNKNOWN",
                    "STREAMING_STRATEGY_EXECUTION_ERROR",
                    "Unexpected error during streaming strategy execution: " + e.getMessage()
            ));
        }
    }

    private <R extends AIResponse> Flux<String> executeAIPipelineStreamingFallback(AIRequest<T> request,
                                                                                   Class<R> responseType,
                                                                                   String sessionId) {
        try {
            PipelineConfiguration config = createPipelineConfiguration();

            return orchestrator.executeStream(request, config)
                    .ofType(String.class)
                    .onErrorResume(error -> {
                        log.error("AI Pipeline streaming fallback failed for session: {}", sessionId, error);
                        return Flux.error(new AIOperationException("All streaming fallback options exhausted for session: " + sessionId, (Throwable) error));
                    });

        } catch (Exception e) {
            log.error("AI Pipeline streaming fallback setup failed for session: {}", sessionId, e);
            return Flux.error(new AIOperationException("Streaming fallback setup failed for session: " + sessionId, e));
        }
    }

    private <R extends AIResponse> R executeAIPipelineFallback(AIRequest<T> request, Class<R> responseType, String sessionId) {
        try {
            PipelineConfiguration config = createPipelineConfiguration();

            Object rawResult = orchestrator.execute(request, config, responseType).block();

            if (responseType.isInstance(rawResult)) {
                return responseType.cast(rawResult);
            } else {
                log.error("Pipeline returned unexpected type: {} for expected: {}",
                        rawResult != null ? rawResult.getClass().getSimpleName() : "null",
                        responseType.getSimpleName());
                throw new AIOperationException("Pipeline returned unexpected response type for session: " + sessionId);
            }

        } catch (AIOperationException e) {
            throw e;
        } catch (Exception e) {
            log.error("AI Pipeline fallback failed for session: {}", sessionId, e);
            throw new AIOperationException("All fallback options exhausted for session: " + sessionId, e);
        }
    }

    private <R extends AIResponse> Mono<R> executeStrategyThroughRegistryAsync(AIRequest<T> request,
                                                                               Class<R> responseType,
                                                                               String sessionId) {
        try {

            return strategyRegistry.executeStrategyAsync(request, responseType)
                    .doOnError(error -> {
                        log.error("Async strategy execution failed for session: {} - {}", sessionId, error.getMessage());
                    });

        } catch (DiagnosisException e) {
            log.error("Async strategy execution failed for session: {} - {}", sessionId, e.getMessage());
            return Mono.error(new AIOperationException("Async strategy execution failed", e));
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

    private void validateResult(AIResponse result, String sessionId) {
        if (result == null) {
            throw new AIOperationException("Strategy execution returned null result for session: " + sessionId);
        }
    }
}