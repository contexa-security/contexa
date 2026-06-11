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
package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class AIStrategyRegistry {

    private final Map<String, AIStrategy<?, ?>> strategies = new HashMap<>();

    @Autowired
    public AIStrategyRegistry(List<AIStrategy<?, ?>> allStrategies) {

        for (AIStrategy<?, ?> strategy : allStrategies) {
            String diagnosis = strategy.getSupportedType().name();

            if (strategies.containsKey(diagnosis)) {
                AIStrategy<?, ?> existing = strategies.get(diagnosis);
                if (strategy.getPriority() < existing.getPriority()) {
                    strategies.put(diagnosis, strategy);
                }
            } else {
                strategies.put(diagnosis, strategy);
            }
        }
    }

    public <T extends DomainContext, R extends AIResponse> AIStrategy<T, R> getStrategy(DiagnosisType diagnosisType) {
        AIStrategy<?, ?> strategy = strategies.get(diagnosisType.name());

        if (strategy == null) {
            throw new DiagnosisException(diagnosisType.name(), "STRATEGY_NOT_FOUND", "Unsupported diagnosisType: " + diagnosisType);
        }
        return (AIStrategy<T, R>) strategy;
    }

    public <R extends AIResponse, T extends DomainContext> R executeStrategy(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {
        return executeStrategyAsync(request, responseType).block(Duration.ofSeconds(5));
    }

    public <R extends AIResponse, T extends DomainContext> Mono<R> executeStrategyAsync(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            return Mono.error(new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "Diagnosis type is not set in the request"));
        }
        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());
        return strategy.executeAsync(request, responseType);
    }

    public <T extends DomainContext, R extends AIResponse> Flux<String> executeStrategyStream(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            return Flux.error(new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "Diagnosis type is not set in the request"));
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());
        return strategy.executeStream(request, responseType);
    }
}
