package io.contexa.contexacore.autonomous.saas.learning.calibration;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.List;

/**
 * Qualification outcome for a calibration profile candidate.
 */
public record CalibrationProfileQualificationDecision(
        boolean qualified,
        LearningArtifactReleaseState recommendedReleaseState,
        List<String> blockingReasons,
        List<String> policyFacts) {

    public CalibrationProfileQualificationDecision {
        recommendedReleaseState = recommendedReleaseState == null ? LearningArtifactReleaseState.COLLECTING : recommendedReleaseState;
        blockingReasons = blockingReasons == null ? List.of() : List.copyOf(blockingReasons);
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}