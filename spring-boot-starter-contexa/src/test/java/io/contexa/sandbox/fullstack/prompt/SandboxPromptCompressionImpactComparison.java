package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

public record SandboxPromptCompressionImpactComparison(
        String budgetProfile,
        String scenarioSelector,
        int roundCount,
        List<SandboxPromptBenchmarkRunResult> promptRunResults,
        List<SandboxDecisionBenchmarkRunResult> decisionRunResults) {

    public SandboxPromptCompressionImpactComparison {
        promptRunResults = promptRunResults == null ? List.of() : List.copyOf(promptRunResults);
        decisionRunResults = decisionRunResults == null ? List.of() : List.copyOf(decisionRunResults);
    }
}
