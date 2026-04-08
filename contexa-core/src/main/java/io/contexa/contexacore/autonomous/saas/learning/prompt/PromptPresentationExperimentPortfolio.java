package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Portfolio summary for prompt presentation experiments.
 */
public record PromptPresentationExperimentPortfolio(
        long promptAuditCount,
        long experimentObservationCount,
        long unclassifiedAuditCount,
        List<PromptPresentationExperimentResult> results,
        LocalDateTime generatedAt) {

    public PromptPresentationExperimentPortfolio {
        promptAuditCount = Math.max(promptAuditCount, 0L);
        experimentObservationCount = Math.max(experimentObservationCount, 0L);
        unclassifiedAuditCount = Math.max(unclassifiedAuditCount, 0L);
        results = results == null ? List.of() : List.copyOf(results);
    }

    public static PromptPresentationExperimentPortfolio empty() {
        return new PromptPresentationExperimentPortfolio(0L, 0L, 0L, List.of(), LocalDateTime.now());
    }
}