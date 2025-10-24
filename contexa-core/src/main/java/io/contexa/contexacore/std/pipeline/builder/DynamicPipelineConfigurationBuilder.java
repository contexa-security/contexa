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

/**
 * 동적 파이프라인 구성 빌더
 *
 * 요청 특성에 따라 파이프라인 단계를 동적으로 선택하고 재구성합니다.
 *
 * 주요 기능:
 * - 조건부 단계 추가 (복잡도 기반, 속도 기반 등)
 * - 커스텀 단계 삽입 (특정 위치에 동적 삽입)
 * - 단계 실행 순서 자동 정렬
 */
@Component
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

    /**
     * 표준 단계 추가 (기본 순서 사용)
     *
     * @param step 파이프라인 단계
     * @param condition 실행 조건
     * @return Builder
     */
    public DynamicPipelineConfigurationBuilder<T> addStandardStep(
            PipelineStep step,
            PipelineStepCondition<T> condition) {

        int order = getStandardStepOrder(step);
        orderedSteps.add(new StepWithOrder(step, null, order));
        stepConditions.put(step, condition);

        log.debug("[DynamicBuilder] 표준 단계 추가: {} (order: {})", step, order);
        return this;
    }

    /**
     * 표준 단계 추가 (항상 실행)
     *
     * @param step 파이프라인 단계
     * @return Builder
     */
    public DynamicPipelineConfigurationBuilder<T> addStandardStep(PipelineStep step) {
        return addStandardStep(step, new AlwaysExecuteCondition<>());
    }

    /**
     * 커스텀 단계 추가
     *
     * @param customStepName 커스텀 단계 이름
     * @param order 실행 순서 (0~100, 낮을수록 먼저 실행)
     * @param condition 실행 조건
     * @return Builder
     */
    public DynamicPipelineConfigurationBuilder<T> addCustomStep(
            String customStepName,
            int order,
            PipelineStepCondition<T> condition) {

        // 레지스트리에서 커스텀 단계 조회
        Optional<io.contexa.contexacore.std.pipeline.step.PipelineStep> stepOpt =
                stepRegistry.getCustomStep(customStepName);

        if (stepOpt.isEmpty()) {
            log.warn("[DynamicBuilder] 커스텀 단계를 찾을 수 없음: {}", customStepName);
            throw new IllegalArgumentException("Custom step not found: " + customStepName);
        }

        io.contexa.contexacore.std.pipeline.step.PipelineStep step = stepOpt.get();
        orderedSteps.add(new StepWithOrder(null, customStepName, order));
        customSteps.put(customStepName, step);

        log.debug("[DynamicBuilder] 커스텀 단계 추가: {} (order: {})", customStepName, order);
        return this;
    }

    /**
     * 특정 표준 단계 이전에 커스텀 단계 삽입
     *
     * @param existingStep 기존 표준 단계
     * @param customStepName 삽입할 커스텀 단계 이름
     * @param condition 실행 조건
     * @return Builder
     */
    public DynamicPipelineConfigurationBuilder<T> insertCustomStepBefore(
            PipelineStep existingStep,
            String customStepName,
            PipelineStepCondition<T> condition) {

        int existingOrder = getStandardStepOrder(existingStep);
        int insertOrder = existingOrder - 1; // 바로 앞에 삽입

        return addCustomStep(customStepName, insertOrder, condition);
    }

    /**
     * 특정 표준 단계 이후에 커스텀 단계 삽입
     *
     * @param existingStep 기존 표준 단계
     * @param customStepName 삽입할 커스텀 단계 이름
     * @param condition 실행 조건
     * @return Builder
     */
    public DynamicPipelineConfigurationBuilder<T> insertCustomStepAfter(
            PipelineStep existingStep,
            String customStepName,
            PipelineStepCondition<T> condition) {

        int existingOrder = getStandardStepOrder(existingStep);
        int insertOrder = existingOrder + 1; // 바로 뒤에 삽입

        return addCustomStep(customStepName, insertOrder, condition);
    }

    /**
     * 파이프라인 구성 빌드
     *
     * @return 완성된 파이프라인 구성
     */
    public PipelineConfiguration<T> build() {
        // 순서대로 정렬
        orderedSteps.sort(Comparator.comparingInt(StepWithOrder::getOrder));

        PipelineConfiguration.Builder<T> builder = PipelineConfiguration.builder();

        // 표준 단계 및 커스텀 단계 추가
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

        log.info("[DynamicBuilder] 파이프라인 구성 완료 - 총 {}개 단계", orderedSteps.size());
        return builder.build();
    }

    /**
     * 표준 단계의 기본 순서 반환
     */
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
                return 50; // 기본값
        }
    }

    /**
     * 내부 클래스: 순서를 가진 단계
     */
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
