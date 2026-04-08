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