package io.contexa.contexacore.autonomous.saas.learning;

/**
 * Common release lifecycle states for learning artifacts.
 */
public enum LearningArtifactReleaseState {
    COLLECTING(false, false),
    SHADOW_READY(false, false),
    REPLAY_READY(false, false),
    CANARY_READY(false, false),
    PROMOTED(true, false),
    REVIEW_ONLY(false, true),
    WITHDRAWN(false, false),
    KILL_SWITCH_ACTIVE(false, false);

    private final boolean runtimeEligible;
    private final boolean reviewState;

    LearningArtifactReleaseState(boolean runtimeEligible, boolean reviewState) {
        this.runtimeEligible = runtimeEligible;
        this.reviewState = reviewState;
    }

    public boolean isRuntimeEligible() {
        return runtimeEligible;
    }

    public boolean isReviewState() {
        return reviewState;
    }

    public boolean isTerminal() {
        return this == WITHDRAWN || this == KILL_SWITCH_ACTIVE;
    }
}
