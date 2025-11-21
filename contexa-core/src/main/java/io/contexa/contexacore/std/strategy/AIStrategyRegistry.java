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

/**
 * AI 전략 레지스트리 (새로운 통합 버전)
 *
 * 기존 DiagnosisStrategyRegistry의 모든 기능을 유지하면서
 * 새로운 AIStrategy 인터페이스를 지원하는 통합 레지스트리
 *
 * 마이그레이션 기간 동안 기존 DiagnosisStrategyRegistry와 공존
 */
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
                    log.info("AI 전략 교체: {} - {} (우선순위: {} → {})",
                            type, strategy.getClass().getSimpleName(),
                            existing.getPriority(), strategy.getPriority());
                } else {
                    log.debug("⏭️ AI 전략 스킵: {} - {} (낮은 우선순위: {})",
                            type, strategy.getClass().getSimpleName(), strategy.getPriority());
                }
            } else {
                strategies.put(type, strategy);
                log.info("AI 전략 등록: {} - {} (우선순위: {})",
                        type, strategy.getClass().getSimpleName(), strategy.getPriority());
            }
        }

        log.info("AIStrategyRegistry 초기화 완료: {} 개 전략 등록", strategies.size());
        logRegisteredStrategies();
    }

    /**
     * 진단 타입에 맞는 전략을 찾아서 반환
     * 새로운 AIStrategy가 없으면 기존 DiagnosisStrategy로 폴백
     */
    public <T extends DomainContext, R extends AIResponse> AIStrategy<T, R> getStrategy(DiagnosisType diagnosisType) {
        AIStrategy<?, ?> strategy = strategies.get(diagnosisType);

        if (strategy == null) {
            throw new DiagnosisException(
                    diagnosisType != null ? diagnosisType.name() : "NULL",
                    "STRATEGY_NOT_FOUND",
                    "지원하지 않는 진단 타입입니다: " + diagnosisType
            );
        }

        return (AIStrategy<T, R>) strategy;
    }

    /**
     * 전략 실행 메서드 (기존 DiagnosisStrategyRegistry.executeStrategy와 동일)
     */
    public <R extends AIResponse, T extends DomainContext> R executeStrategy(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            throw new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "요청에 진단 타입이 설정되지 않았습니다");
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        log.debug("진단 실행 (완전 비동기): {} 전략 사용 - {}",
                request.getDiagnosisType(), strategy.getClass().getSimpleName());

        try {
            return strategy.executeAsync(request, responseType)
                    .doOnSuccess(result -> log.debug("비동기 전략 실행 완료: {}", strategy.getClass().getSimpleName()))
                    .doOnError(error -> log.error("비동기 전략 실행 실패: {}", strategy.getClass().getSimpleName(), error))
                    .block(Duration.ofMinutes(5)); // 최대 5분 타임아웃으로 안전하게 대기
        } catch (Exception e) {
            log.error("전략 실행 중 예외 발생: {}", strategy.getClass().getSimpleName(), e);
            throw new DiagnosisException(
                    request.getDiagnosisType().name(),
                    "STRATEGY_EXECUTION_ERROR",
                    "전략 실행 중 오류가 발생했습니다: " + e.getMessage()
            );
        }
    }

    /**
     * 비동기 전략 실행 메서드 (기존과 동일)
     */
    public <R extends AIResponse, T extends DomainContext> Mono<R> executeStrategyAsync(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            return Mono.error(new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "요청에 진단 타입이 설정되지 않았습니다"));
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        log.debug("비동기 진단 실행: {} 전략 사용 - {}",
                request.getDiagnosisType(), strategy.getClass().getSimpleName());

        return strategy.executeAsync(request, responseType);
    }

    /**
     * 스트리밍 전략 실행 메서드 (기존과 동일)
     */
    public <T extends DomainContext, R extends AIResponse> Flux<String> executeStrategyStream(AIRequest<T> request, Class<R> responseType)
            throws DiagnosisException {

        if (request.getDiagnosisType() == null) {
            return Flux.error(new DiagnosisException("NULL", "MISSING_DIAGNOSIS_TYPE",
                    "요청에 진단 타입이 설정되지 않았습니다"));
        }

        AIStrategy<T, R> strategy = getStrategy(request.getDiagnosisType());

        log.debug("스트리밍 진단 실행: {} 전략 사용 - {}",
                request.getDiagnosisType(), strategy.getClass().getSimpleName());

        if (!strategy.supportsStreaming()) {
            // 스트리밍을 지원하지 않는 경우 폴백 처리
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

    /**
     * 문자열을 청크로 분할하여 Flux로 반환 (기존과 동일)
     */
    private Flux<String> splitStringIntoFlux(String text, int chunkSize) {
        List<String> chunks = new java.util.ArrayList<>();
        for (int i = 0; i < text.length(); i += chunkSize) {
            chunks.add(text.substring(i, Math.min(text.length(), i + chunkSize)));
        }
        return Flux.fromIterable(chunks);
    }

    /**
     * 등록된 모든 전략 정보를 반환 (기존과 동일)
     */
    public Map<DiagnosisType, String> getRegisteredStrategies() {
        Map<DiagnosisType, String> result = new HashMap<>();
        strategies.forEach((type, strategy) ->
                result.put(type, strategy.getClass().getSimpleName()));
        return result;
    }

    /**
     * 특정 진단 타입이 지원되는지 확인 (기존과 동일)
     */
    public boolean isSupported(DiagnosisType diagnosisType) {
        return strategies.containsKey(diagnosisType);
    }

    /**
     * 특정 작업이 지원되는지 확인 (기존과 동일)
     */
    public boolean supportsOperation(String operation) {
        if (operation == null || operation.trim().isEmpty()) {
            return false;
        }

        // 새 전략에서 먼저 확인
        return strategies.values().stream()
                .anyMatch(strategy -> {
                    String strategyName = strategy.getClass().getSimpleName().toLowerCase();
                    String operationLower = operation.toLowerCase();
                    return strategyName.contains(operationLower) ||
                            strategy.getDescription().toLowerCase().contains(operationLower);
                });
    }

    /**
     * 등록된 전략들을 로그로 출력 (기존과 동일)
     */
    private void logRegisteredStrategies() {
        log.info("등록된 AI 전략들 (새로운 버전):");
        strategies.forEach((type, strategy) ->
                log.info("  - {}: {} (우선순위: {})",
                        type.getDisplayName(),
                        strategy.getClass().getSimpleName(),
                        strategy.getPriority()));
    }
}
