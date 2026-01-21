package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

@FunctionalInterface
public interface PipelineStepCondition<T extends DomainContext> {

    boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context);

    default String getConditionDescription() {
        return this.getClass().getSimpleName();
    }

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
