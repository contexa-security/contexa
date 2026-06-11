/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
