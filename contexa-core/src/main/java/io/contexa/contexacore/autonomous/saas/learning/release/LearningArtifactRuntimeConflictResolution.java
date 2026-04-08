package io.contexa.contexacore.autonomous.saas.learning.release;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import java.util.List;
/**
 * Runtime conflict resolution result.
 */
public record LearningArtifactRuntimeConflictResolution(
        LearningArtifactRuntimeConflictCause cause,
        LearningArtifactRuntimeRemediationAction remediationAction,
        LearningArtifactReleaseState resultingReleaseState,
        boolean recorded,
        String reason,
        List<String> policyFacts) {
    public LearningArtifactRuntimeConflictResolution {
        cause = cause == null ? LearningArtifactRuntimeConflictCause.NONE : cause;
        remediationAction = remediationAction == null ? LearningArtifactRuntimeRemediationAction.NO_ACTION : remediationAction;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}
