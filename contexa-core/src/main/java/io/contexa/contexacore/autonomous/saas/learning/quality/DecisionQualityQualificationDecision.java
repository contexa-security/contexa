package io.contexa.contexacore.autonomous.saas.learning.quality;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.List;

/**
 * Qualification outcome for a decision-quality profile candidate.
 */
public record DecisionQualityQualificationDecision(
        boolean qualified,
        LearningArtifactReleaseState recommendedReleaseState,
        List<String> blockingReasons,
        List<String> policyFacts) {

    public DecisionQualityQualificationDecision {
        recommendedReleaseState = recommendedReleaseState == null ? LearningArtifactReleaseState.COLLECTING : recommendedReleaseState;
        blockingReasons = blockingReasons == null ? List.of() : List.copyOf(blockingReasons);
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}