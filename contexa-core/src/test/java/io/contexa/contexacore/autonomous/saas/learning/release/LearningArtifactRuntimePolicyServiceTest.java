package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LearningArtifactRuntimePolicyServiceTest {

    private final LearningArtifactRuntimePolicyService service = new LearningArtifactRuntimePolicyService();

    @Test
    @DisplayName("promoted artifact should be runtime-ready only after tenant opt-in")
    void shouldRequireTenantOptInForPromotedArtifacts() {
        LearningArtifactMetadata promoted = new LearningArtifactMetadata(LearningArtifactReleaseState.PROMOTED, null, null);

        LearningArtifactRuntimePolicyDecision blocked = service.evaluate(promoted, false, false);
        LearningArtifactRuntimePolicyDecision allowed = service.evaluate(promoted, true, false);

        assertThat(blocked.policyState()).isEqualTo("TENANT_OPT_IN_REQUIRED");
        assertThat(blocked.runtimeAllowed()).isFalse();
        assertThat(blocked.deploymentAction()).isEqualTo("WITHHOLD");
        assertThat(allowed.policyState()).isEqualTo("READY");
        assertThat(allowed.runtimeAllowed()).isTrue();
        assertThat(allowed.deploymentAction()).isEqualTo("ALLOW_RUNTIME");
    }

    @Test
    @DisplayName("review-only artifacts should stay withheld regardless of tenant opt-in")
    void shouldKeepReviewOnlyArtifactsWithheld() {
        LearningArtifactMetadata reviewOnly = new LearningArtifactMetadata(LearningArtifactReleaseState.REVIEW_ONLY, null, null);

        LearningArtifactRuntimePolicyDecision decision = service.evaluate(reviewOnly, true, false);

        assertThat(decision.policyState()).isEqualTo("REVIEW_ONLY");
        assertThat(decision.reviewOnly()).isTrue();
        assertThat(decision.runtimeAllowed()).isFalse();
        assertThat(decision.deploymentAction()).isEqualTo("WITHHOLD");
    }

    @Test
    @DisplayName("withdrawn and kill-switch states should force runtime withdrawal")
    void shouldWithdrawWhenRuntimeIsDisabled() {
        LearningArtifactMetadata withdrawn = new LearningArtifactMetadata(LearningArtifactReleaseState.WITHDRAWN, null, null);
        LearningArtifactMetadata promoted = new LearningArtifactMetadata(LearningArtifactReleaseState.PROMOTED, null, null);

        LearningArtifactRuntimePolicyDecision withdrawnDecision = service.evaluate(withdrawn, true, false);
        LearningArtifactRuntimePolicyDecision killSwitchDecision = service.evaluate(promoted, true, true);

        assertThat(withdrawnDecision.policyState()).isEqualTo("WITHDRAWN");
        assertThat(withdrawnDecision.withdrawn()).isTrue();
        assertThat(withdrawnDecision.deploymentAction()).isEqualTo("WITHDRAW");
        assertThat(killSwitchDecision.policyState()).isEqualTo("KILL_SWITCH_ACTIVE");
        assertThat(killSwitchDecision.killSwitchActive()).isTrue();
        assertThat(killSwitchDecision.deploymentAction()).isEqualTo("WITHDRAW");
    }

    @Test
    @DisplayName("pre-promotion lifecycle states should remain withheld")
    void shouldWithholdPrePromotionStates() {
        LearningArtifactMetadata canaryReady = new LearningArtifactMetadata(LearningArtifactReleaseState.CANARY_READY, null, null);

        LearningArtifactRuntimePolicyDecision decision = service.evaluate(canaryReady, true, false);

        assertThat(decision.policyState()).isEqualTo("CANARY_READY");
        assertThat(decision.runtimeAllowed()).isFalse();
        assertThat(decision.deploymentAction()).isEqualTo("WITHHOLD");
    }
}
