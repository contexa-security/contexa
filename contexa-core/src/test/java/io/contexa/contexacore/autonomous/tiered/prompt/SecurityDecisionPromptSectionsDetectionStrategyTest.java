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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionPromptSectionsDetectionStrategyTest {

    @Test
    void buildThreatLearningSectionIncludesPromotedDetectionStrategiesAsSupportingContext() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setDetectionStrategyRuntimePack(new DetectionStrategyRuntimePack(
                "tenant-acme",
                true,
                List.of(new DetectionStrategyRuntimePack.RuntimeStrategyItem(
                        "strategy-post-mfa",
                        "2026.04.08-v1",
                        "POST_MFA_SURFACE_JUMP",
                        List.of("ACCOUNT_TAKEOVER"),
                        List.of("mfa_verified", "admin_surface_jump"),
                        List.of("new_device", "failed_login_burst"),
                        List.of("NEW_DEVICE_POST_MFA_SENSITIVE"),
                        12L,
                        "HIGH",
                        new LearningArtifactMetadata(
                                LearningArtifactReleaseState.PROMOTED,
                                new LearningArtifactMetrics(48L, 0.82d, 0.74d, 0.31d, 0.05d, -0.12d),
                                List.of()),
                        List.of("Observed higher takeover detection after post-MFA surface shift prioritization."),
                        List.of("Release gate confirmed runtime promotion for this strategy."))),
                LocalDateTime.of(2026, 4, 8, 11, 0)));

        String section = sections.buildThreatLearningSection(behaviorAnalysis);

        assertThat(section).contains("PROMOTED DETECTION STRATEGIES");
        assertThat(section).contains("supporting context only");
        assertThat(section).contains("POST_MFA_SURFACE_JUMP");
        assertThat(section).contains("RequiredSignals:");
        assertThat(section).contains("Observed higher takeover detection");
    }
}
