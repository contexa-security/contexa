package io.contexa.contexacore.autonomous.saas.learning.release;

/**
 * Event types recorded by the learning artifact release ledger.
 */
public enum LearningArtifactReleaseLedgerEventType {
    ARTIFACT_CREATED,
    CANARY_RESULT_RECORDED,
    ROLLBACK_RECORDED,
    WITHDRAWN,
    KILL_SWITCH_ACTIVATED,
    KILL_SWITCH_CLEARED
}
