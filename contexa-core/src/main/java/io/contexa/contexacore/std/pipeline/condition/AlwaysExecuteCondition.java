package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

/**
 * 항상 실행하는 조건
 *
 * 모든 요청에 대해 해당 단계를 실행합니다.
 * 기본 동작으로 사용됩니다.
 */
public class AlwaysExecuteCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        return true;
    }

    @Override
    public String getConditionDescription() {
        return "항상 실행";
    }
}
