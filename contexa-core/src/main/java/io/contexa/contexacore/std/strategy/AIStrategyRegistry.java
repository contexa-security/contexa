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
            throw new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE", "요청에 진단 타입이 설정되지 않았습니다");
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        try {
            return strategy.executeAsync(request, responseType)
                    .doOnSuccess(result -> log.debug("비동기 전략 실행 완료: {}", strategy.getClass().getSimpleName()))
                    .doOnError(error -> log.error("비동기 전략 실행 실패: {}", strategy.getClass().getSimpleName(), error))
                    .block(Duration.ofMinutes(5));
        } catch (Exception e) {
            log.error("전략 실행 중 예외 발생: {}", strategy.getClass().getSimpleName(), e);
            throw new DiagnosisException(
                    request.getDiagnosisType().name(),
                    "STRATEGY_EXECUTION_ERROR",
                    "전략 실행 중 오류가 발생했습니다: " + e.getMessage()
            );
        }
    }

    public <R extends AIResponse, T extends DomainContext> Mono<R> executeStrategyAsync(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            return Mono.error(new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "요청에 진단 타입이 설정되지 않았습니다"));
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        return strategy.executeAsync(request, responseType);
    }

    public <T extends DomainContext, R extends AIResponse> Flux<String> executeStrategyStream(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            return Flux.error(new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "요청에 진단 타입이 설정되지 않았습니다"));
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        if (!strategy.supportsStreaming()) {

            log.warn("전략 {}이 스트리밍을 지원하지 않아 비동기 처리 후 변환합니다",
                    strategy.getClass().getSimpleName());

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
                        log.error("비동기 전략 실행 실패", e);
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
