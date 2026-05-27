package io.contexa.contexacore.autonomous.context.prompt;

@FunctionalInterface
public interface PromptSlotPlanProvider {

    PromptSlotPlan planFor(String sectionKey, String labelKey);

    default PromptSlotPlan planForLabel(String labelKey) {
        return planFor(null, labelKey);
    }

    default String cacheScopeKey() {
        return "UNSCOPED";
    }

    static PromptSlotPlanProvider unscoped() {
        return PromptSlotPlan::unscoped;
    }
}
