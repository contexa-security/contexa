package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 범용 AI 전략 인터페이스
 *
 * 모든 AI 진단 전략이 구현해야 하는 통합 API
 * 기존 DiagnosisStrategy의 기능을 모두 포함하면서 표준화된 인터페이스 제공
 *
 * @param <T> DomainContext 타입 (IAMContext 등)
 * @param <R> AIResponse 타입 (IAMResponse 등)
 */
public interface AIStrategy<T extends DomainContext, R extends AIResponse> {

    /**
     * 이 전략이 지원하는 진단 타입을 반환
     * 기존 DiagnosisStrategy.getSupportedType()과 동일
     */
    DiagnosisType getSupportedType();

    /**
     * 전략의 우선순위 (낮을수록 높은 우선순위)
     * 기존 DiagnosisStrategy.getPriority()와 동일
     */
    int getPriority();

    /**
     * AI 진단을 동기적으로 실행
     * 기존 DiagnosisStrategy.execute()와 동일
     */
    R execute(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    /**
     * AI 진단을 비동기로 실행
     * 기존 DiagnosisStrategy.executeAsync()와 동일
     */
    Mono<R> executeAsync(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    /**
     * 스트리밍 방식으로 진단 실행
     * 기존 StreamingDiagnosisStrategy.executeStream()과 동일
     */
    Flux<String> executeStream(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    /**
     * 스트리밍 지원 여부
     * 기본값: false (하위 호환성 유지)
     */
    default boolean supportsStreaming() {
        return false;
    }

    /**
     * 주어진 요청을 처리할 수 있는지 확인
     * 기존 DiagnosisStrategy.canHandle()과 동일
     */
    default boolean canHandle(AIRequest<T> request) {
        return request.getDiagnosisType() == getSupportedType();
    }

    /**
     * 전략 설명 반환
     * 기존 DiagnosisStrategy.getDescription()과 동일
     */
    default String getDescription() {
        return getSupportedType().getDescription();
    }

    /**
     * 동적 파이프라인: 요청에 최적화된 파이프라인 구성 제안
     *
     * @param request AI 요청
     * @param characteristics 요청 특성 분석 결과
     * @return 제안된 파이프라인 구성 (null이면 기본 구성 사용)
     */
    default io.contexa.contexacore.std.pipeline.PipelineConfiguration<T> suggestPipelineConfiguration(
            AIRequest<T> request,
            io.contexa.contexacore.std.pipeline.analyzer.RequestCharacteristics characteristics) {
        // 기본값: null 반환 (기본 파이프라인 사용)
        return null;
    }
}
