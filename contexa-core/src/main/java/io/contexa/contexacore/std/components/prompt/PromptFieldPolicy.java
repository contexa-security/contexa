package io.contexa.contexacore.std.components.prompt;

import java.util.List;

public record PromptFieldPolicy(
        String requiredPolicy,
        String applicabilityRule,
        String projectionPolicy,
        String qualityRelevance,
        List<String> metricCodes,
        String remediationOwner,
        String notApplicableRule,
        boolean officialContractField) {

    public PromptFieldPolicy {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
    }
}
