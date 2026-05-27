package io.contexa.contexacore.autonomous.context.prompt;

public record PromptRuntimeGovernanceRuleApplication(
        String ruleId,
        String sourceActionId,
        String slotKey,
        String ruleType,
        String appliedOperation,
        boolean changedPrompt,
        String resultState,
        String beforePromptHash,
        String afterPromptHash) {
}
