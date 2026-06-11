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

import io.contexa.contexacore.autonomous.saas.dto.DecisionQualityProfileSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DecisionQualityProfileSnapshotAssemblerTest {

    private final DecisionQualityProfileSnapshotAssembler assembler = new DecisionQualityProfileSnapshotAssembler();

    @Test
    void assemblesSnapshot() {
        LearningArtifactMetadata metadata = new LearningArtifactMetadata(
                LearningArtifactReleaseState.PROMOTED,
                new LearningArtifactMetrics(12L, 0.75d, 0.20d, 0.10d, -0.04d, 0.03d),
                List.of(new LearningArtifactGuardrail("bias-reviewed", "Bias risk reviewed", true)));
        DecisionQualityProfileCandidate candidate = new DecisionQualityProfileCandidate(
                new DecisionQualityScenarioResult(
                        "SESSION_PATH_SIMILARITY_BREAK",
                        new DecisionBiasAggregationResult(12L, 10L, 2L, 1L, 0.20d, 0.10d, 0.25d, 0.10d, List.of("aggregated")),
                        List.of("evidence")),
                metadata,
                List.of("policy"));

        DecisionQualityProfileSnapshot snapshot = assembler.assembleSnapshot("tenant-a", true, true, List.of(candidate));

        assertThat(snapshot.runtimeReady()).isTrue();
        assertThat(snapshot.promotedProfileCount()).isEqualTo(1L);
        assertThat(snapshot.profiles()).hasSize(1);
        assertThat(snapshot.profiles().get(0).profileKey()).isEqualTo("decision-quality-profile/session-path-similarity-break");
    }
}
