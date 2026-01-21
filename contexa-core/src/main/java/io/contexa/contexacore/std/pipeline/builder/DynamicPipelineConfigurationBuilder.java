package io.contexa.contexacore.std.pipeline.builder;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration.PipelineStep;
import io.contexa.contexacore.std.pipeline.condition.AlwaysExecuteCondition;
import io.contexa.contexacore.std.pipeline.condition.PipelineStepCondition;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class DynamicPipelineConfigurationBuilder<T extends DomainContext> {

    private final CustomPipelineStepRegistry stepRegistry;
    private final List<StepWithOrder> orderedSteps = new ArrayList<>();
    private final Map<PipelineStep, PipelineStepCondition<T>> stepConditions = new HashMap<>();
    private final Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps = new HashMap<>();

    @Autowired
    public DynamicPipelineConfigurationBuilder(CustomPipelineStepRegistry stepRegistry) {
        this.stepRegistry = stepRegistry;
    }

    public DynamicPipelineConfigurationBuilder<T> addStandardStep(
            PipelineStep step,
            PipelineStepCondition<T> condition) {

        int order = getStandardStepOrder(step);
        orderedSteps.add(new StepWithOrder(step, null, order));
        stepConditions.put(step, condition);

                return this;
    }

    public DynamicPipelineConfigurationBuilder<T> addStandardStep(PipelineStep step) {
        return addStandardStep(step, new AlwaysExecuteCondition<>());
    }

    public DynamicPipelineConfigurationBuilder<T> addCustomStep(
            String customStepName,
            int order,
            PipelineStepCondition<T> condition) {

        Optional<io.contexa.contexacore.std.pipeline.step.PipelineStep> stepOpt =
                stepRegistry.getCustomStep(customStepName);

        if (stepOpt.isEmpty()) {
            log.warn("[DynamicBuilder] 커스텀 단계를 찾을 수 없음: {}", customStepName);
            throw new IllegalArgumentException("Custom step not found: " + customStepName);
        }

        io.contexa.contexacore.std.pipeline.step.PipelineStep step = stepOpt.get();
        orderedSteps.add(new StepWithOrder(null, customStepName, order));
        customSteps.put(customStepName, step);

                return this;
    }

    public DynamicPipelineConfigurationBuilder<T> insertCustomStepBefore(
            PipelineStep existingStep,
            String customStepName,
            PipelineStepCondition<T> condition) {

        int existingOrder = getStandardStepOrder(existingStep);
        int insertOrder = existingOrder - 1; 

        return addCustomStep(customStepName, insertOrder, condition);
    }

    public DynamicPipelineConfigurationBuilder<T> insertCustomStepAfter(
            PipelineStep existingStep,
            String customStepName,
            PipelineStepCondition<T> condition) {

        int existingOrder = getStandardStepOrder(existingStep);
        int insertOrder = existingOrder + 1; 

        return addCustomStep(customStepName, insertOrder, condition);
    }

    public PipelineConfiguration<T> build() {
        
        orderedSteps.sort(Comparator.comparingInt(StepWithOrder::getOrder));

        PipelineConfiguration.Builder<T> builder = PipelineConfiguration.builder();

        for (StepWithOrder stepWithOrder : orderedSteps) {
            if (stepWithOrder.isStandardStep()) {
                PipelineStep step = stepWithOrder.getStandardStep();
                PipelineStepCondition<T> condition = stepConditions.get(step);

                builder.addStep(step);
                if (condition != null) {
                    builder.setStepCondition(step, condition);
                }
            } else {
                String customStepName = stepWithOrder.getCustomStepName();
                io.contexa.contexacore.std.pipeline.step.PipelineStep customStep = customSteps.get(customStepName);

                if (customStep != null) {
                    builder.addCustomStep(customStepName, customStep);
                }
            }
        }

                return builder.build();
    }

    private int getStandardStepOrder(PipelineStep step) {
        switch (step) {
            case PREPROCESSING:
                return 10;
            case CONTEXT_RETRIEVAL:
                return 20;
            case PROMPT_GENERATION:
                return 30;
            case LLM_EXECUTION:
                return 40;
            case SOAR_TOOL_EXECUTION:
                return 50;
            case RESPONSE_PARSING:
                return 60;
            case POSTPROCESSING:
                return 70;
            default:
                return 50; 
        }
    }

    private static class StepWithOrder {
        private final PipelineStep standardStep;
        private final String customStepName;
        private final int order;

        public StepWithOrder(PipelineStep standardStep, String customStepName, int order) {
            this.standardStep = standardStep;
            this.customStepName = customStepName;
            this.order = order;
        }

        public boolean isStandardStep() {
            return standardStep != null;
        }

        public PipelineStep getStandardStep() {
            return standardStep;
        }

        public String getCustomStepName() {
            return customStepName;
        }

        public int getOrder() {
            return order;
        }
    }
}
