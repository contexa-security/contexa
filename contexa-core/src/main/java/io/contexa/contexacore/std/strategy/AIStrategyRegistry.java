package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.DiagnosisType;
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

    private final Map<DiagnosisType, AIStrategy<?, ?>> strategies = new HashMap<>();

    @Autowired
    public AIStrategyRegistry(List<AIStrategy<?, ?>> allStrategies) {

        for (AIStrategy<?, ?> strategy : allStrategies) {
            DiagnosisType type = strategy.getSupportedType();

            if (strategies.containsKey(type)) {
                AIStrategy<?, ?> existing = strategies.get(type);
                if (strategy.getPriority() < existing.getPriority()) {
                    strategies.put(type, strategy);
                }
            } else {
                strategies.put(type, strategy);
            }
        }
    }

    public <T extends DomainContext, R extends AIResponse> AIStrategy<T, R> getStrategy(DiagnosisType diagnosisType) {
        AIStrategy<?, ?> strategy = strategies.get(diagnosisType);

        if (strategy == null) {
            throw new DiagnosisException(
                    diagnosisType != null ? diagnosisType.name() : "NULL",
                    "STRATEGY_NOT_FOUND",
                    "Unsupported diagnosisType: " + diagnosisType
            );
        }

        return (AIStrategy<T, R>) strategy;
    }

    public <R extends AIResponse, T extends DomainContext> R executeStrategy(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            throw new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE", "Diagnosis type is not set in the request");
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        try {
            return strategy.executeAsync(request, responseType)
                    .doOnError(error -> log.error("Async strategy execution failed: {}", strategy.getClass().getSimpleName(), error))
                    .block(Duration.ofMinutes(5));
        } catch (Exception e) {
            log.error("Exception occurred during strategy execution: {}", strategy.getClass().getSimpleName(), e);
            throw new DiagnosisException(
                    request.getDiagnosisType().name(),
                    "STRATEGY_EXECUTION_ERROR",
                    "Error occurred during strategy execution: " + e.getMessage()
            );
        }
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

        if (!strategy.supportsStreaming()) {
            return strategy.executeAsync(request, responseType)
                    .flatMapMany(result -> {
                        Object resultData = result.getData();
                        if (resultData instanceof String resultString) {
                            return splitStringIntoFlux(resultString, 100);
                        } else {
                            return Flux.just(resultData.toString());
                        }
                    })
                    .onErrorResume(Exception.class, e -> {
                        log.error("Async strategy execution failed", e);
                        return Flux.error(e);
                    });
        }

        return strategy.executeStream(request, responseType);
    }

    private Flux<String> splitStringIntoFlux(String text, int chunkSize) {
        List<String> chunks = new java.util.ArrayList<>();
        for (int i = 0; i < text.length(); i += chunkSize) {
            chunks.add(text.substring(i, Math.min(text.length(), i + chunkSize)));
        }
        return Flux.fromIterable(chunks);
    }

    public Map<DiagnosisType, String> getRegisteredStrategies() {
        Map<DiagnosisType, String> result = new HashMap<>();
        strategies.forEach((type, strategy) ->
                result.put(type, strategy.getClass().getSimpleName()));
        return result;
    }

    public boolean isSupported(DiagnosisType diagnosisType) {
        return strategies.containsKey(diagnosisType);
    }

    public boolean supportsOperation(String operation) {
        if (operation == null || operation.trim().isEmpty()) {
            return false;
        }

        return strategies.values().stream()
                .anyMatch(strategy -> {
                    String strategyName = strategy.getClass().getSimpleName().toLowerCase();
                    String operationLower = operation.toLowerCase();
                    return strategyName.contains(operationLower) ||
                            strategy.getDescription().toLowerCase().contains(operationLower);
                });
    }
}
