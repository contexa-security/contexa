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

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionPromptSectionsCohortSeedTest {

    @Test
    void buildCohortBaselineSeedSectionIncludesRuntimeWeightAndPolicyFacts() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setCohortSeedApplied(true);
        behaviorAnalysis.setOrganizationBaselineEstablished(true);
        behaviorAnalysis.setCohortSeedSupportingDimensions(List.of("ACCESS_HOURS", "OPERATING_SYSTEMS"));
        behaviorAnalysis.setCohortBaselineSeed(new BaselineSeedSnapshot(
                "tenant-a", true, true, true, "FINTECH_APAC_LARGE", "FINTECH", "APAC", 18, 420L,
                List.of(9, 10), List.of(1, 2), List.of("WINDOWS"), Map.of(), Map.of(), Map.of(),
                LocalDate.of(2026, 4, 8), LocalDateTime.of(2026, 4, 8, 12, 0)));
        behaviorAnalysis.setCohortSeedWeight(0.15d);
        behaviorAnalysis.setCohortSeedWeightState("DEGRADED_ESTABLISHED_BASELINES");
        behaviorAnalysis.setCohortSeedPolicyFacts(List.of(
                "Both personal and organization baselines are established.",
                "Runtime weight 0.15 applies to cohort FINTECH_APAC_LARGE."));

        String section = sections.buildCohortBaselineSeedSection(behaviorAnalysis);

        assertThat(section).contains("COHORT BASELINE SEED");
        assertThat(section).contains("Runtime weight: 15% (DEGRADED_ESTABLISHED_BASELINES)");
        assertThat(section).contains("Seed policy: Both personal and organization baselines are established.");
        assertThat(section).contains("Seed policy: Runtime weight 0.15 applies to cohort FINTECH_APAC_LARGE.");
    }
}
