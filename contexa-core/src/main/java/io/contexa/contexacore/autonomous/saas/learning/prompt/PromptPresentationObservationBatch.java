package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.util.List;

/**
 * Prepared observation batch for presentation experiments.
 */
public record PromptPresentationObservationBatch(
        long promptAuditCount,
        long unclassifiedAuditCount,
        List<PromptPresentationObservation> observations) {

    public PromptPresentationObservationBatch {
        promptAuditCount = Math.max(promptAuditCount, 0L);
        unclassifiedAuditCount = Math.max(unclassifiedAuditCount, 0L);
        observations = observations == null ? List.of() : List.copyOf(observations);
    }

    public static PromptPresentationObservationBatch empty() {
        return new PromptPresentationObservationBatch(0L, 0L, List.of());
    }
}