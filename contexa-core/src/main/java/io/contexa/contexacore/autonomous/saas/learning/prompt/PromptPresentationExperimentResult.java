package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.util.List;

/**
 * Aggregated experimental result for a single presentation pattern.
 */
public record PromptPresentationExperimentResult(
        PromptPresentationPatternProfile patternProfile,
        long sampleSize,
        long operatorReviewedOutcomeCount,
        long reviewerDisagreementCount,
        long falsePositiveOutcomeCount,
        long falseNegativeOutcomeCount,
        long omissionLinkedCount,
        long telemetryLinkedCount,
        double averageDeniedContextCount,
        double averageOmittedSectionCount,
        double averagePromptBudgetUtilizationRate,
        List<String> evidenceFacts,
        List<String> policyFacts) {

    public PromptPresentationExperimentResult {
        patternProfile = patternProfile == null ? PromptPresentationPatternProfile.unclassified() : patternProfile;
        sampleSize = Math.max(sampleSize, 0L);
        operatorReviewedOutcomeCount = Math.max(operatorReviewedOutcomeCount, 0L);
        reviewerDisagreementCount = Math.max(reviewerDisagreementCount, 0L);
        falsePositiveOutcomeCount = Math.max(falsePositiveOutcomeCount, 0L);
        falseNegativeOutcomeCount = Math.max(falseNegativeOutcomeCount, 0L);
        omissionLinkedCount = Math.max(omissionLinkedCount, 0L);
        telemetryLinkedCount = Math.max(telemetryLinkedCount, 0L);
        averageDeniedContextCount = finiteOrZero(averageDeniedContextCount);
        averageOmittedSectionCount = finiteOrZero(averageOmittedSectionCount);
        averagePromptBudgetUtilizationRate = finiteOrZero(averagePromptBudgetUtilizationRate);
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }

    private static double finiteOrZero(double value) {
        return Double.isFinite(value) ? value : 0.0d;
    }
}