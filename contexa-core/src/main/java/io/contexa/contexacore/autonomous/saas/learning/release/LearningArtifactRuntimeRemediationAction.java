package io.contexa.contexacore.autonomous.saas.learning.release;
/**
 * Remediation action selected for a runtime artifact conflict.
 */
public enum LearningArtifactRuntimeRemediationAction {
    NO_ACTION,
    DOWNGRADE_TO_REVIEW_ONLY,
    WITHDRAW_ARTIFACT,
    ACTIVATE_KILL_SWITCH
}
