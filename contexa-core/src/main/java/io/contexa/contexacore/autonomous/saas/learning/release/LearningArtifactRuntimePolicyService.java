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

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates common runtime policy for learning artifacts.
 */
public class LearningArtifactRuntimePolicyService {

    public LearningArtifactRuntimePolicyDecision evaluate(
            LearningArtifactMetadata metadata,
            boolean tenantOptIn,
            boolean tenantKillSwitchActive) {
        LearningArtifactMetadata current = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
        LearningArtifactReleaseState releaseState = current.releaseState();
        List<String> facts = new ArrayList<>();
        facts.add("releaseState=" + releaseState.name());
        facts.add("tenantOptIn=" + tenantOptIn);
        facts.add("tenantKillSwitchActive=" + tenantKillSwitchActive);

        if (tenantKillSwitchActive || releaseState == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE) {
            facts.add("Runtime policy blocks deployment because kill switch is active.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    tenantOptIn,
                    true,
                    false,
                    false,
                    releaseState == LearningArtifactReleaseState.WITHDRAWN,
                    "KILL_SWITCH_ACTIVE",
                    "WITHDRAW",
                    facts);
        }

        if (releaseState == LearningArtifactReleaseState.WITHDRAWN) {
            facts.add("Runtime policy withdraws the artifact because release state is WITHDRAWN.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    tenantOptIn,
                    false,
                    false,
                    false,
                    true,
                    "WITHDRAWN",
                    "WITHDRAW",
                    facts);
        }

        if (releaseState == LearningArtifactReleaseState.REVIEW_ONLY) {
            facts.add("Runtime policy keeps the artifact in review-only mode.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    tenantOptIn,
                    false,
                    false,
                    true,
                    false,
                    "REVIEW_ONLY",
                    "WITHHOLD",
                    facts);
        }

        if (releaseState == LearningArtifactReleaseState.PROMOTED) {
            if (!tenantOptIn) {
                facts.add("Runtime policy requires tenant opt-in before promoted artifacts can be enabled.");
                return new LearningArtifactRuntimePolicyDecision(
                        releaseState,
                        false,
                        false,
                        false,
                        false,
                        false,
                        "TENANT_OPT_IN_REQUIRED",
                        "WITHHOLD",
                        facts);
            }
            facts.add("Runtime policy allows the promoted artifact because tenant opt-in is active.");
            return new LearningArtifactRuntimePolicyDecision(
                    releaseState,
                    true,
                    false,
                    true,
                    false,
                    false,
                    "READY",
                    "ALLOW_RUNTIME",
                    facts);
        }

        facts.add("Runtime policy withholds the artifact until the release lifecycle reaches PROMOTED.");
        return new LearningArtifactRuntimePolicyDecision(
                releaseState,
                tenantOptIn,
                false,
                false,
                false,
                false,
                releaseState.name(),
                "WITHHOLD",
                facts);
    }
}
