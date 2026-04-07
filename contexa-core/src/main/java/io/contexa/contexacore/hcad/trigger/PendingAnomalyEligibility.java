package io.contexa.contexacore.hcad.trigger;

public record PendingAnomalyEligibility(
        String userId,
        String contextBindingHash,
        String baseKey
) {
}
