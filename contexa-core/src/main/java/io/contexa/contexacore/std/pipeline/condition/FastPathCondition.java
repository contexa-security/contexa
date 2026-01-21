package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FastPathCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        
        Boolean requiresFast = context.get("requires_fast_response", Boolean.class);

        if (requiresFast != null && requiresFast) {
                        return false;
        }

                return true;
    }

    @Override
    public String getConditionDescription() {
        return "고속 경로가 아닐 때만 실행";
    }
}
