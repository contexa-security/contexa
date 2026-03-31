package io.contexa.contexacore.std.components.prompt;

public class IdentityLLMViewComposer implements LLMViewComposer {

    @Override
    public PromptViewComposition compose(String rawSystemPrompt, String rawUserPrompt, PromptBudgetProfile budgetProfile) {
        return new PromptViewComposition(
                rawSystemPrompt,
                rawUserPrompt,
                rawSystemPrompt,
                rawUserPrompt,
                PromptCompressionLedger.identity(rawSystemPrompt, rawUserPrompt));
    }
}