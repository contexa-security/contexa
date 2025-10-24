package io.contexa.contexacore.std.strategy;

import lombok.Builder;
import lombok.Getter;

/**
 * 파이프라인 구성 설정
 *
 * Strategy가 원하는 파이프라인 동작을 선언적으로 정의합니다.
 * AbstractAIStrategy가 이 설정과 RequestCharacteristics를 조합하여 최적의 파이프라인을 생성합니다.
 */
@Getter
@Builder
public class PipelineConfig {

    /**
     * 컨텍스트 조회 전략
     */
    private final ContextRetrievalStrategy contextRetrieval;

    /**
     * 후처리 전략
     */
    private final PostProcessingStrategy postProcessing;

    /**
     * 타임아웃 (초)
     */
    @Builder.Default
    private final int timeoutSeconds = 300;

    /**
     * 추가 메타데이터
     */
    private final String description;

    /**
     * 컨텍스트 조회 전략
     */
    public enum ContextRetrievalStrategy {
        /**
         * 항상 컨텍스트 조회 필요 (기존 데이터 참조가 필수인 경우)
         * 예: 정책 생성, 보안 분석
         */
        ALWAYS_REQUIRED,

        /**
         * 복잡도에 따라 동적 결정 (AbstractAIStrategy의 동적 로직 사용)
         * 예: 리소스 네이밍
         */
        DYNAMIC,

        /**
         * 컨텍스트 조회 선택적 (간단한 요청은 생략 가능)
         * 예: 단순 템플릿 생성
         */
        OPTIONAL
    }

    /**
     * 후처리 전략
     */
    public enum PostProcessingStrategy {
        /**
         * 항상 후처리 실행 (정확도가 중요한 경우)
         */
        ALWAYS,

        /**
         * 복잡도에 따라 동적 결정 (AbstractAIStrategy의 동적 로직 사용)
         */
        DYNAMIC,

        /**
         * 빠른 응답을 위해 후처리 생략 가능
         */
        FAST_PATH
    }

    /**
     * 기본 설정: 모든 단계 동적 결정
     */
    public static PipelineConfig defaultConfig() {
        return PipelineConfig.builder()
                .contextRetrieval(ContextRetrievalStrategy.DYNAMIC)
                .postProcessing(PostProcessingStrategy.DYNAMIC)
                .description("기본 동적 구성")
                .build();
    }

    /**
     * 전체 파이프라인 구성: 모든 단계 필수
     */
    public static PipelineConfig fullPipeline() {
        return PipelineConfig.builder()
                .contextRetrieval(ContextRetrievalStrategy.ALWAYS_REQUIRED)
                .postProcessing(PostProcessingStrategy.ALWAYS)
                .description("전체 파이프라인")
                .build();
    }

    /**
     * 빠른 응답 구성: 최소한의 단계만 실행
     */
    public static PipelineConfig fastResponse() {
        return PipelineConfig.builder()
                .contextRetrieval(ContextRetrievalStrategy.OPTIONAL)
                .postProcessing(PostProcessingStrategy.FAST_PATH)
                .description("빠른 응답")
                .build();
    }
}
