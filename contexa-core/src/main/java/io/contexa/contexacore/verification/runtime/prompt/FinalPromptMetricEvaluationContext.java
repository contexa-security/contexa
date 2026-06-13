package io.contexa.contexacore.verification.runtime.prompt;

public record FinalPromptMetricEvaluationContext(
        FinalPromptEvaluationInput input
) {

    public FinalPromptSnapshot prompt() {
        return input == null ? null : input.prompt();
    }

    public FinalPromptSemanticModel semanticModel() {
        return input == null || input.semanticModel() == null ? FinalPromptSemanticModel.empty() : input.semanticModel();
    }

    public FinalPromptEvidenceContext evidence() {
        return input == null ? null : input.evidence();
    }
}
