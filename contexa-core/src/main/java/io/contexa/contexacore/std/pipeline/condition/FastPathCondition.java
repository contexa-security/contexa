package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * 고속 경로 조건
 *
 * 빠른 응답이 필요하지 않을 때만 실행되는 조건입니다.
 * 지연 시간이 중요한 경우 일부 단계를 건너뛰는데 사용됩니다.
 *
 * 사용 예시:
 * - 전처리 단계를 고속 경로에서 생략
 * - 후처리 단계를 고속 경로에서 생략
 */
@Slf4j
public class FastPathCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        // requiresFastResponse가 true면 건너뜀 (false 반환)
        Boolean requiresFast = context.get("requires_fast_response", Boolean.class);

        if (requiresFast != null && requiresFast) {
            log.debug("[FastPath] 고속 경로 요청 - 단계 건너뜀");
            return false;
        }

        log.debug("[FastPath] 일반 경로 - 단계 실행");
        return true;
    }

    @Override
    public String getConditionDescription() {
        return "고속 경로가 아닐 때만 실행";
    }
}
