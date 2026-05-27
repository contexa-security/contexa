package io.contexa.contexacore.autonomous.context.prompt;

import java.util.List;

public record PromptRuntimeGovernanceRuleApplicationResult(
        String userPrompt,
        List<PromptRuntimeGovernanceRuleApplication> applications) {
}
