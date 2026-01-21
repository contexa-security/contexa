package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ContextRetrievalOptionalCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        
        Boolean requiresContext = context.get("requires_context_retrieval", Boolean.class);

        if (requiresContext == null) {
            
                        return true;
        }

        return requiresContext;
    }

    @Override
    public String getConditionDescription() {
        return "컨텍스트 검색 필요 시에만 실행";
    }
}
