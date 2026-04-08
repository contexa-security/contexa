package io.contexa.contexacore.autonomous.saas.learning;

/**
 * Common lifecycle contract for learning artifacts.
 */
public interface LearningArtifactLifecycle {

    LearningArtifactReleaseState releaseState();

    default boolean isCollecting() {
        return releaseState() == LearningArtifactReleaseState.COLLECTING;
    }

    default boolean isShadowReady() {
        return releaseState() == LearningArtifactReleaseState.SHADOW_READY;
    }

    default boolean isReplayReady() {
        return releaseState() == LearningArtifactReleaseState.REPLAY_READY;
    }

    default boolean isCanaryReady() {
        return releaseState() == LearningArtifactReleaseState.CANARY_READY;
    }

    default boolean isPromoted() {
        return releaseState() == LearningArtifactReleaseState.PROMOTED;
    }

    default boolean isReviewOnly() {
        return releaseState() == LearningArtifactReleaseState.REVIEW_ONLY;
    }

    default boolean isWithdrawn() {
        return releaseState() == LearningArtifactReleaseState.WITHDRAWN;
    }

    default boolean isKillSwitchActive() {
        return releaseState() == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE;
    }

    default boolean isRuntimeEligible() {
        return releaseState().isRuntimeEligible();
    }
}
