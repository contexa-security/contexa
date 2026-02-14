package io.contexa.contexacore.std.operations;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class DistributedStrategyExecutor<T extends DomainContext> {
    private final AIStrategyRegistry strategyRegistry;

    @Autowired
    public DistributedStrategyExecutor(AIStrategyRegistry strategyRegistry) {
        this.strategyRegistry = strategyRegistry;
    }

    public <R extends AIResponse> Mono<R> executeDistributedStrategyAsync(AIRequest<T> request, Class<R> responseType, String sessionId) {

        return executeStrategyThroughRegistryAsync(request, responseType, sessionId)
                .doOnSuccess(result -> {
                    validateResult(result, sessionId);
                })
                .onErrorResume(error -> {
                    log.error("ASYNC strategy execution failed for session: {}", sessionId, error);
                    return Mono.error(new AIOperationException("Pipeline returned unexpected response type for session: " + sessionId));
                });
    }

    public <R extends AIResponse> Flux<String> executeDistributedStrategyStream(AIRequest<T> request,
                                                                                Class<R> responseType,
                                                                                String sessionId,
                                                                                String auditId) {
        try {
            return executeStrategyThroughRegistryStream(request, responseType, sessionId)
                    .doOnError(error -> {
                        log.error("Streaming strategy execution failed for session: {} - {}", sessionId, error.getMessage());
                    });

        } catch (Exception e) {
            log.error("Distributed streaming strategy execution failed for session: {}", sessionId, e);
            return Flux.error(new AIOperationException("Streaming strategy execution failed", e));
        }
    }

    private <R extends AIResponse> Flux<String> executeStrategyThroughRegistryStream(AIRequest<T> request,
                                                                                     Class<R> responseType,
                                                                                     String sessionId) {
        try {
            return strategyRegistry.executeStrategyStream(request, responseType)
                    .doOnError(error -> log.error("Real-time streaming strategy execution failed for session: {}", sessionId, error));

        } catch (DiagnosisException e) {
            log.error("Unexpected error in streaming strategy execution for session: {}", sessionId, e);
            return Flux.error(new DiagnosisException(
                    request.getDiagnosisType() != null ? request.getDiagnosisType().name() : "UNKNOWN",
                    "STREAMING_STRATEGY_EXECUTION_ERROR",
                    "Unexpected error during streaming strategy execution: " + e.getMessage()
            ));
        }
    }

    private <R extends AIResponse> Mono<R> executeStrategyThroughRegistryAsync(AIRequest<T> request, Class<R> responseType, String sessionId) {
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

    private void validateResult(AIResponse result, String sessionId) {
        if (result == null) {
            throw new AIOperationException("Strategy execution returned null result for session: " + sessionId);
        }
    }
}