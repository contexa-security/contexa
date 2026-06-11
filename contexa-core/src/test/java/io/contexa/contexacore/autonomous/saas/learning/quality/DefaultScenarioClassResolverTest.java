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
package io.contexa.contexacore.autonomous.saas.learning.quality;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultScenarioClassResolverTest {

    private final DefaultScenarioClassResolver resolver = new DefaultScenarioClassResolver();

    @Test
    void resolvesNewDevicePostMfaSensitive() {
        ScenarioClassResolution resolution = resolver.resolve(observation(
                Map.of(
                        "isNewDevice", true,
                        "mfaVerified", true,
                        "requestPath", "/admin/report/export"),
                List.of("new_device"),
                List.of("post-mfa elevation observed")));

        assertThat(resolution.scenarioClass()).isEqualTo(DefaultScenarioClassResolver.NEW_DEVICE_POST_MFA_SENSITIVE);
    }

    @Test
    void resolvesLowDiversityExportApproach() {
        ScenarioClassResolution resolution = resolver.resolve(observation(
                Map.of(
                        "requestPath", "/report/export/monthly",
                        "lowDiversity", true),
                List.of("report_export"),
                List.of("narrow path approach preserved")));

        assertThat(resolution.scenarioClass()).isEqualTo(DefaultScenarioClassResolver.LOW_DIVERSITY_EXPORT_APPROACH);
    }

    @Test
    void resolvesSessionPathSimilarityBreak() {
        ScenarioClassResolution resolution = resolver.resolve(observation(
                Map.of("requestPath", "/admin/approval/review"),
                List.of("session_path_similarity_break"),
                List.of("sequence break before approval")));

        assertThat(resolution.scenarioClass()).isEqualTo(DefaultScenarioClassResolver.SESSION_PATH_SIMILARITY_BREAK);
    }

    @Test
    void leavesWeakObservationUnresolved() {
        ScenarioClassResolution resolution = resolver.resolve(observation(
                Map.of("requestPath", "/profile"),
                List.of("profile_view"),
                List.of("normal navigation")));

        assertThat(resolution.isResolved()).isFalse();
    }

    private DecisionQualityObservation observation(
            Map<String, Object> scenarioSignals,
            List<String> signalKeys,
            List<String> evidenceFacts) {
        return new DecisionQualityObservation(
                "corr-1",
                "ALLOW",
                "ALLOW",
                "NONE",
                "OPERATOR_REVIEWED",
                "ALLOW",
                "ALLOW",
                0.81d,
                2,
                true,
                1,
                true,
                signalKeys,
                scenarioSignals,
                evidenceFacts);
    }
}
