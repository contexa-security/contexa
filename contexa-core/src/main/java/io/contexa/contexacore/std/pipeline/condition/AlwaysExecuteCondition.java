package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

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
