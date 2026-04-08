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
