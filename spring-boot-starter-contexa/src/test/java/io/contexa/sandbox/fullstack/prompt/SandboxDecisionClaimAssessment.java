package io.contexa.sandbox.fullstack.prompt;

public record SandboxDecisionClaimAssessment(
        String claim,
        SandboxDecisionClaimVerdict verdict,
        String rationale) {
}
