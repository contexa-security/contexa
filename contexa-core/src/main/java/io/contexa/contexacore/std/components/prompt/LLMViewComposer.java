package io.contexa.contexacore.std.components.prompt;

public interface LLMViewComposer {

    PromptViewComposition compose(String rawSystemPrompt, String rawUserPrompt, PromptBudgetProfile budgetProfile);
}