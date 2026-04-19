package io.contexa.contexacore.autonomous.learning.evidence;

public record CurrentVsObservedDeltaSnapshot(
        String key,
        String currentValue,
        String observedValuesSummary,
        boolean observed,
        String description,
        LearningEvidenceScope sourceScope) {
}
