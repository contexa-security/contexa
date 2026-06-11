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
package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultCohortSeedExpansionServiceTest {

    private final DefaultCohortSeedExpansionService service = new DefaultCohortSeedExpansionService();

    @Test
    void expandsBaselineSeedWithSequenceBandAndTransitionPriors() {
        BaselineSeedSnapshot snapshot = new BaselineSeedSnapshot(
                "tenant-a",
                true,
                true,
                true,
                "FINTECH_APAC_LARGE",
                "FINTECH",
                "APAC",
                18,
                420L,
                List.of(9, 10),
                List.of(1, 2),
                List.of("WINDOWS", "MACOS"),
                Map.of("9", 32L),
                Map.of("1", 14L),
                Map.of("WINDOWS", 22L),
                LocalDate.of(2026, 4, 8),
                LocalDateTime.of(2026, 4, 8, 12, 0));
        CohortSeedQualificationDecision qualification = new CohortSeedQualificationDecision(
                true,
                CohortSeedSupportLevel.STRONG,
                LearningArtifactReleaseState.SHADOW_READY,
                List.of(),
                List.of("qualified"));

        CohortSeedPackSnapshot expanded = service.expand(new CohortSeedExpansionInput(
                snapshot,
                qualification,
                "LARGE",
                24L,
                12.5d,
                Map.of("LOGIN>PROFILE>EXPORT", 14L, "LOGIN>ADMIN>DOWNLOAD", 9L),
                Map.of("SHORT", 6L, "MEDIUM", 11L, "LONG", 4L),
                Map.of("PROFILE->EXPORT", 12L, "ADMIN->DOWNLOAD", 8L)));

        assertThat(expanded.seedQualified()).isTrue();
        assertThat(expanded.cohortKey()).isEqualTo("fintech/apac/large");
        assertThat(expanded.supportLevel()).isEqualTo("STRONG");
        assertThat(expanded.promotionState()).isEqualTo("SHADOW_READY");
        assertThat(expanded.earlyAssessmentSampleCount()).isEqualTo(24L);
        assertThat(expanded.earlyQualityImprovementDelta()).isEqualTo(12.5d);
        assertThat(expanded.firstSequenceFamilies()).extracting(CohortSeedPackSnapshot.DistributionItem::key)
                .containsExactly("LOGIN>PROFILE>EXPORT", "LOGIN>ADMIN>DOWNLOAD");
        assertThat(expanded.sessionLengthBands()).extracting(CohortSeedPackSnapshot.DistributionItem::key)
                .containsExactly("MEDIUM", "SHORT", "LONG");
        assertThat(expanded.surfaceTransitionPriors()).extracting(CohortSeedPackSnapshot.DistributionItem::key)
                .containsExactly("PROFILE->EXPORT", "ADMIN->DOWNLOAD");
    }

    @Test
    void returnsEmptySnapshotWhenBaselineSeedIsMissing() {
        CohortSeedPackSnapshot expanded = service.expand(new CohortSeedExpansionInput(
                null,
                null,
                null,
                0L,
                0.0d,
                Map.of(),
                Map.of(),
                Map.of()));

        assertThat(expanded.seedAvailable()).isFalse();
        assertThat(expanded.seedQualified()).isFalse();
        assertThat(expanded.firstSequenceFamilies()).isEmpty();
    }
}