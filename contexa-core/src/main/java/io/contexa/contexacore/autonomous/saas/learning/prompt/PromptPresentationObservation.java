package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.util.List;

/**
 * Correlated observation used for prompt presentation experiments.
 */
public record PromptPresentationObservation(
        String correlationId,
        PromptPresentationPatternProfile patternProfile,
        boolean promptRuntimeTelemetryLinked,
        boolean modelPerformanceTelemetryLinked,
        boolean operatorReviewedOutcome,
        boolean reviewerDisagreement,
        boolean falsePositiveOutcome,
        boolean falseNegativeOutcome,
        int deniedContextCount,
        int omittedSectionCount,
        int promptOmissionCount,
        double promptBudgetUtilizationRate,
        List<String> evidenceFacts) {

    public PromptPresentationObservation {
        patternProfile = patternProfile == null ? PromptPresentationPatternProfile.unclassified() : patternProfile;
        deniedContextCount = Math.max(deniedContextCount, 0);
        omittedSectionCount = Math.max(omittedSectionCount, 0);
        promptOmissionCount = Math.max(promptOmissionCount, 0);
        promptBudgetUtilizationRate = Double.isFinite(promptBudgetUtilizationRate) ? promptBudgetUtilizationRate : 0.0d;
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}