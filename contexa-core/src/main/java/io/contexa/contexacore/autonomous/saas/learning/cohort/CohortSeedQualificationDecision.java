package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.List;

/**
 * Qualification decision for cohort seed runtime eligibility.
 */
public record CohortSeedQualificationDecision(
        boolean qualified,
        CohortSeedSupportLevel supportLevel,
        LearningArtifactReleaseState recommendedReleaseState,
        List<String> blockingReasons,
        List<String> policyFacts) {

    public CohortSeedQualificationDecision {
        supportLevel = supportLevel == null ? CohortSeedSupportLevel.INSUFFICIENT : supportLevel;
        recommendedReleaseState = recommendedReleaseState == null ? LearningArtifactReleaseState.COLLECTING : recommendedReleaseState;
        blockingReasons = blockingReasons == null ? List.of() : List.copyOf(blockingReasons);
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}