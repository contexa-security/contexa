package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

/**
 * 파이프라인 단계 실행 조건 인터페이스
 *
 * 각 파이프라인 단계가 실행되어야 하는지를 동적으로 결정합니다.
 *
 * 사용 예시:
 * - 간단한 분류 작업은 컨텍스트 검색 생략
 * - 빠른 응답이 필요한 경우 전처리 단계 생략
 * - 복잡도가 높은 경우에만 특정 단계 실행
 */
@FunctionalInterface
public interface PipelineStepCondition<T extends DomainContext> {

    /**
     * 단계 실행 여부 결정
     *
     * @param request AI 요청
     * @param context 파이프라인 실행 컨텍스트
     * @return true면 실행, false면 건너뜀
     */
    boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context);

    /**
     * 조건 설명 (디버깅 및 로깅용)
     */
    default String getConditionDescription() {
        return this.getClass().getSimpleName();
    }

    /**
     * AND 조건 조합
     */
    default PipelineStepCondition<T> and(PipelineStepCondition<T> other) {
        return new PipelineStepCondition<T>() {
            @Override
            public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
                return PipelineStepCondition.this.shouldExecute(request, context)
                    && other.shouldExecute(request, context);
            }

            @Override
            public String getConditionDescription() {
                return PipelineStepCondition.this.getConditionDescription()
                    + " AND " + other.getConditionDescription();
            }
        };
    }

    /**
     * OR 조건 조합
     */
    default PipelineStepCondition<T> or(PipelineStepCondition<T> other) {
        return new PipelineStepCondition<T>() {
            @Override
            public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
                return PipelineStepCondition.this.shouldExecute(request, context)
                    || other.shouldExecute(request, context);
            }

            @Override
            public String getConditionDescription() {
                return PipelineStepCondition.this.getConditionDescription()
                    + " OR " + other.getConditionDescription();
            }
        };
    }

    /**
     * NOT 조건
     */
    default PipelineStepCondition<T> negate() {
        return new PipelineStepCondition<T>() {
            @Override
            public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
                return !PipelineStepCondition.this.shouldExecute(request, context);
            }

            @Override
            public String getConditionDescription() {
                return "NOT " + PipelineStepCondition.this.getConditionDescription();
            }
        };
    }
}
