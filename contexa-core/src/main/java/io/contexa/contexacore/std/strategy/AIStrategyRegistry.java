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
            throw new DiagnosisException(request.getDiagnosisType().name,
                    "STRATEGY_EXECUTION_ERROR", "Error occurred during strategy execution: " + e.getMessage());
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

    public Map<String, String> getRegisteredStrategies() {
        Map<String, String> result = new HashMap<>();
        strategies.forEach((type, strategy) ->
                result.put(type, strategy.getClass().getSimpleName()));
        return result;
    }
}
