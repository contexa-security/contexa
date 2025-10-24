package io.contexa.contexacore.std.pipeline.analyzer;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

/**
 * 요청 특성 분석기 인터페이스
 *
 * AI 요청을 분석하여 파이프라인 최적화에 필요한 특성을 추출합니다.
 * 분석 결과는 RequestCharacteristics 객체로 반환됩니다.
 *
 * 주요 분석 항목:
 * - 요청 복잡도
 * - 컨텍스트 검색 필요 여부
 * - 응답 속도 민감도
 * - 정확도 요구사항
 */
public interface RequestAnalyzer {

    /**
     * 요청 특성 분석
     *
     * @param request AI 요청
     * @param <T> DomainContext 타입
     * @return 분석된 요청 특성
     */
    <T extends DomainContext> RequestCharacteristics analyze(AIRequest<T> request);

    /**
     * 분석기 이름
     *
     * @return 분석기 식별자
     */
    String getAnalyzerName();
}
