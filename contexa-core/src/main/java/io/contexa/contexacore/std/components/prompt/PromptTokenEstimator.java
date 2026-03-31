package io.contexa.contexacore.std.components.prompt;

public interface PromptTokenEstimator {

    PromptTokenEstimate estimate(String systemPrompt, String userPrompt, PromptBudgetProfile budgetProfile);
}
