package io.contexa.contexacore.std.components.prompt;

public interface LLMViewComposer {

    PromptViewComposition compose(String rawSystemPrompt, String rawUserPrompt, PromptBudgetProfile budgetProfile);

    default PromptViewComposition compose(
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptBudgetProfile budgetProfile,
            String modelHint) {
        return compose(rawSystemPrompt, rawUserPrompt, budgetProfile);
    }
}
