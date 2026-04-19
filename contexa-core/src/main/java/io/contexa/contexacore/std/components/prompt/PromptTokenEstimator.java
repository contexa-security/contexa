package io.contexa.contexacore.std.components.prompt;

public interface PromptTokenEstimator {

    PromptTokenEstimate estimate(
            String modelHint,
            String systemPrompt,
            String userPrompt,
            PromptBudgetProfile budgetProfile);

    default PromptTokenEstimate estimate(String systemPrompt, String userPrompt, PromptBudgetProfile budgetProfile) {
        return estimate(null, systemPrompt, userPrompt, budgetProfile);
    }

    default boolean supports(String modelHint) {
        return false;
    }
}
