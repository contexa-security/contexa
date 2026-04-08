package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.List;

/**
 * Qualification outcome for a strategy family prior to artifact assembly.
 */
public record StrategyEvidenceQualificationDecision(
        boolean qualified,
        LearningArtifactReleaseState recommendedReleaseState,
        List<String> blockingReasons,
        List<String> policyFacts) {

    public StrategyEvidenceQualificationDecision {
        recommendedReleaseState = recommendedReleaseState == null
                ? LearningArtifactReleaseState.COLLECTING
                : recommendedReleaseState;
        blockingReasons = blockingReasons == null ? List.of() : List.copyOf(blockingReasons);
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}
