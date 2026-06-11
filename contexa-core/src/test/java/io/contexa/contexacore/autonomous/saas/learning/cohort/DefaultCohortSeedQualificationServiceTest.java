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
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultCohortSeedQualificationServiceTest {

    private final DefaultCohortSeedQualificationService service = new DefaultCohortSeedQualificationService();

    @Test
    void qualifiesStrongCohortSeedWhenSupportAndImprovementAreSufficient() {
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

        CohortSeedQualificationDecision decision = service.qualify(new CohortSeedQualificationInput(snapshot, 24L, 12.5d));

        assertThat(decision.qualified()).isTrue();
        assertThat(decision.supportLevel()).isEqualTo(CohortSeedSupportLevel.STRONG);
        assertThat(decision.recommendedReleaseState()).isEqualTo(LearningArtifactReleaseState.SHADOW_READY);
        assertThat(decision.blockingReasons()).isEmpty();
    }

    @Test
    void keepsSeedCollectingWhenSupportIsInsufficient() {
        BaselineSeedSnapshot snapshot = new BaselineSeedSnapshot(
                "tenant-b",
                true,
                true,
                false,
                "GENERAL_SMALL",
                "GENERAL",
                "GLOBAL",
                2,
                25L,
                List.of(),
                List.of(),
                List.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                LocalDate.of(2026, 4, 8),
                LocalDateTime.of(2026, 4, 8, 12, 0));

        CohortSeedQualificationDecision decision = service.qualify(new CohortSeedQualificationInput(snapshot, 6L, 1.5d));

        assertThat(decision.qualified()).isFalse();
        assertThat(decision.supportLevel()).isEqualTo(CohortSeedSupportLevel.INSUFFICIENT);
        assertThat(decision.recommendedReleaseState()).isEqualTo(LearningArtifactReleaseState.COLLECTING);
        assertThat(decision.blockingReasons()).hasSizeGreaterThanOrEqualTo(4);
    }
}