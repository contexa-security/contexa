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