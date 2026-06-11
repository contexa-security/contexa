/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

    public <R extends AIResponse> Mono<R> executeDistributedStrategyAsync(AIRequest<T> request, Class<R> responseType) {

        return executeStrategyThroughRegistryAsync(request, responseType)
                .doOnSuccess(this::validateResult)
                .onErrorResume(error -> {
                    log.error("ASYNC strategy execution failed", error);
                    return Mono.error(new AIOperationException("Pipeline returned unexpected response type"));
                });
    }

    public <R extends AIResponse> Flux<String> executeDistributedStrategyStream(AIRequest<T> request,
                                                                                Class<R> responseType,
                                                                                String auditId) {
        try {
            return executeStrategyThroughRegistryStream(request, responseType)
                    .doOnError(error -> {
                        log.error("Streaming strategy execution failed - {}", error.getMessage());
                    });

        } catch (Exception e) {
            log.error("Distributed streaming strategy execution failed", e);
            return Flux.error(new AIOperationException("Streaming strategy execution failed", e));
        }
    }

    private <R extends AIResponse> Flux<String> executeStrategyThroughRegistryStream(AIRequest<T> request,
                                                                                     Class<R> responseType) {
        try {
            return strategyRegistry.executeStrategyStream(request, responseType)
                    .doOnError(error -> log.error("Real-time streaming strategy execution failed", error));

        } catch (DiagnosisException e) {
            log.error("Unexpected error in streaming strategy execution", e);
            return Flux.error(new DiagnosisException(
                    request.getDiagnosisType() != null ? request.getDiagnosisType().name() : "UNKNOWN",
                    "STREAMING_STRATEGY_EXECUTION_ERROR",
                    "Unexpected error during streaming strategy execution: " + e.getMessage()
            ));
        }
    }

    private <R extends AIResponse> Mono<R> executeStrategyThroughRegistryAsync(AIRequest<T> request, Class<R> responseType) {
        try {
            return strategyRegistry.executeStrategyAsync(request, responseType)
                    .doOnError(error -> {
                        log.error("Async strategy execution failed - {}", error.getMessage());
                    });

        } catch (DiagnosisException e) {
            log.error("Async strategy execution failed - {}", e.getMessage());
            return Mono.error(new AIOperationException("Async strategy execution failed", e));
        }
    }

    private void validateResult(AIResponse result) {
        if (result == null) {
            throw new AIOperationException("Strategy execution returned null result");
        }
    }
}
