package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LearningArtifactReleaseServiceTest {

    private final LearningArtifactReleaseService service = new LearningArtifactReleaseService();

    @Test
    @DisplayName("release lifecycle should follow the governed progression path")
    void shouldFollowGovernedProgression() {
        LearningArtifactMetadata collecting = LearningArtifactMetadata.collecting();

        LearningArtifactMetadata shadowReady = service.transition(collecting, LearningArtifactReleaseState.SHADOW_READY);
        LearningArtifactMetadata replayReady = service.transition(shadowReady, LearningArtifactReleaseState.REPLAY_READY);
        LearningArtifactMetadata canaryReady = service.transition(replayReady, LearningArtifactReleaseState.CANARY_READY);
        LearningArtifactMetadata promoted = service.transition(canaryReady, LearningArtifactReleaseState.PROMOTED);

        assertThat(shadowReady.releaseState()).isEqualTo(LearningArtifactReleaseState.SHADOW_READY);
        assertThat(replayReady.releaseState()).isEqualTo(LearningArtifactReleaseState.REPLAY_READY);
        assertThat(canaryReady.releaseState()).isEqualTo(LearningArtifactReleaseState.CANARY_READY);
        assertThat(promoted.releaseState()).isEqualTo(LearningArtifactReleaseState.PROMOTED);
        assertThat(promoted.isRuntimeEligible()).isTrue();
    }

    @Test
    @DisplayName("release lifecycle should reject skipped promotion transitions")
    void shouldRejectSkippedPromotionTransitions() {
        assertThatThrownBy(() -> service.transition(LearningArtifactMetadata.collecting(), LearningArtifactReleaseState.PROMOTED))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("COLLECTING")
                .hasMessageContaining("PROMOTED");
    }

    @Test
    @DisplayName("review only state should re-enter the governed path without direct promotion")
    void shouldAllowReviewOnlyReentryButNotDirectPromotion() {
        LearningArtifactReleaseTransition preview = service.preview(LearningArtifactReleaseState.REVIEW_ONLY, LearningArtifactReleaseState.CANARY_READY);
        LearningArtifactReleaseTransition blockedPreview = service.preview(LearningArtifactReleaseState.REVIEW_ONLY, LearningArtifactReleaseState.PROMOTED);

        assertThat(preview.allowed()).isTrue();
        assertThat(preview.allowedTargets()).contains(LearningArtifactReleaseState.SHADOW_READY, LearningArtifactReleaseState.REPLAY_READY, LearningArtifactReleaseState.CANARY_READY);
        assertThat(blockedPreview.allowed()).isFalse();
    }

    @Test
    @DisplayName("terminal states should only allow no-op transitions")
    void shouldTreatTerminalStatesAsTerminal() {
        LearningArtifactMetadata withdrawn = new LearningArtifactMetadata(LearningArtifactReleaseState.WITHDRAWN, null, null);

        assertThat(service.transition(withdrawn, LearningArtifactReleaseState.WITHDRAWN)).isSameAs(withdrawn);
        assertThatThrownBy(() -> service.transition(withdrawn, LearningArtifactReleaseState.SHADOW_READY))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("WITHDRAWN");
    }
}
