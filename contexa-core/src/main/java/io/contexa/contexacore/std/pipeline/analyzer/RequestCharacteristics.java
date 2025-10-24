package io.contexa.contexacore.std.pipeline.analyzer;

import lombok.Builder;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

/**
 * 요청 특성 분석 결과
 *
 * AIStrategy가 파이프라인 구성을 결정하는데 필요한 요청 특성을 담고 있습니다.
 * RequestAnalyzer가 AI 요청을 분석하여 이 객체를 생성합니다.
 */
@Getter
@Builder
public class RequestCharacteristics {

    /**
     * 요청 복잡도 (0.0 ~ 1.0)
     * - 0.0 ~ 0.3: 간단한 요청 (단순 분류, 조회)
     * - 0.3 ~ 0.7: 중간 복잡도 (일반적인 분석)
     * - 0.7 ~ 1.0: 높은 복잡도 (복합 분석, 추론)
     */
    private final double complexity;

    /**
     * RAG 컨텍스트 검색 필요 여부
     * - true: 과거 데이터, 문서, 패턴 검색 필요
     * - false: 요청 자체 정보만으로 처리 가능
     */
    private final boolean requiresContextRetrieval;

    /**
     * 빠른 응답 필요 여부 (지연 시간 민감도)
     * - true: 실시간 응답 필요 (< 200ms 목표)
     * - false: 정확도 우선 (1~2초 허용)
     */
    private final boolean requiresFastResponse;

    /**
     * 높은 정확도 필요 여부
     * - true: 후처리 단계 필수 (검증, 정제)
     * - false: 기본 응답으로 충분
     */
    private final boolean requiresHighAccuracy;

    /**
     * 예상 데이터 볼륨 (바이트)
     */
    private final int estimatedDataVolume;

    /**
     * 요청 타입 분류
     * - "CLASSIFICATION": 분류 작업
     * - "GENERATION": 생성 작업
     * - "ANALYSIS": 분석 작업
     * - "SYNTHESIS": 종합 작업
     */
    private final String requestType;

    /**
     * 추가 메타데이터 (도메인별 특성)
     */
    @Builder.Default
    private final Map<String, Object> metadata = new HashMap<>();

    /**
     * 컨텍스트로 변환 (PipelineExecutionContext에 저장용)
     *
     * @return 키-값 맵으로 변환된 특성 데이터
     */
    public Map<String, Object> toContextMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("request_complexity", complexity);
        map.put("requires_context_retrieval", requiresContextRetrieval);
        map.put("requires_fast_response", requiresFastResponse);
        map.put("requires_high_accuracy", requiresHighAccuracy);
        map.put("estimated_data_volume", estimatedDataVolume);
        map.put("request_type", requestType);
        map.putAll(metadata);
        return map;
    }

    @Override
    public String toString() {
        return String.format(
            "RequestCharacteristics[complexity=%.2f, contextRetrieval=%s, fastResponse=%s, highAccuracy=%s, type=%s]",
            complexity, requiresContextRetrieval, requiresFastResponse, requiresHighAccuracy, requestType
        );
    }
}
