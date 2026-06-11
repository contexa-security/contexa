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
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultCohortSeedRuntimeWeightPolicyTest {

    private final DefaultCohortSeedRuntimeWeightPolicy policy = new DefaultCohortSeedRuntimeWeightPolicy();

    @Test
    void degradesWeightWhenBothLocalBaselinesAreEstablished() {
        BaselineSeedSnapshot snapshot = new BaselineSeedSnapshot(
                "tenant-a", true, true, true, "FINTECH_APAC_LARGE", "FINTECH", "APAC", 18, 420L,
                List.of(9, 10), List.of(1, 2), List.of("WINDOWS"), Map.of(), Map.of(), Map.of(),
                LocalDate.of(2026, 4, 8), LocalDateTime.of(2026, 4, 8, 12, 0));

        CohortSeedRuntimeWeightDecision decision = policy.evaluate(snapshot, true, true);

        assertThat(decision.seedAllowed()).isTrue();
        assertThat(decision.runtimeWeight()).isEqualTo(0.15d);
        assertThat(decision.weightState()).isEqualTo(CohortSeedRuntimeWeightState.DEGRADED_ESTABLISHED_BASELINES);
    }

    @Test
    void keepsFullWeightDuringColdStart() {
        BaselineSeedSnapshot snapshot = new BaselineSeedSnapshot(
                "tenant-a", true, true, true, "FINTECH_APAC_LARGE", "FINTECH", "APAC", 18, 420L,
                List.of(9, 10), List.of(1, 2), List.of("WINDOWS"), Map.of(), Map.of(), Map.of(),
                LocalDate.of(2026, 4, 8), LocalDateTime.of(2026, 4, 8, 12, 0));

        CohortSeedRuntimeWeightDecision decision = policy.evaluate(snapshot, false, false);

        assertThat(decision.seedAllowed()).isTrue();
        assertThat(decision.runtimeWeight()).isEqualTo(1.0d);
        assertThat(decision.weightState()).isEqualTo(CohortSeedRuntimeWeightState.FULL_COLD_START_SUPPORT);
    }
}