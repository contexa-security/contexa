package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.List;

/**
 * Preview of a release lifecycle transition.
 */
public record LearningArtifactReleaseTransition(
        LearningArtifactReleaseState currentState,
        LearningArtifactReleaseState targetState,
        boolean allowed,
        boolean noOp,
        boolean runtimeEligibleBefore,
        boolean runtimeEligibleAfter,
        List<LearningArtifactReleaseState> allowedTargets) {

    public LearningArtifactReleaseTransition {
        allowedTargets = allowedTargets == null ? List.of() : List.copyOf(allowedTargets);
    }
}
