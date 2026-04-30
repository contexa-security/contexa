package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LearningArtifactRuntimeConflictServiceTest {

    private final InMemoryLearningArtifactReleaseLedgerStore store = new InMemoryLearningArtifactReleaseLedgerStore();
    private final LearningArtifactReleaseLedgerService ledgerService = new LearningArtifactReleaseLedgerService(store);
    private final LearningArtifactRuntimeConflictService runtimeConflictService =
            new LearningArtifactRuntimeConflictService(ledgerService);

    @Test
    void recordsReviewOnlyRollbackAndSuppressesRuntimeReuse() {
        boolean recorded = runtimeConflictService.recordReviewOnlyConflict(
                "tenant-a",
                LearningArtifactTypeNames.DECISION_QUALITY_PROFILE,
                "profile/new-device-post-mfa-sensitive",
                "2026.04.08-v1",
                "Local truth overrode promoted decision-quality profile.",
                List.of("scenarioClass=NEW_DEVICE_POST_MFA_SENSITIVE"));

        assertThat(recorded).isTrue();
        assertThat(runtimeConflictService.isRuntimeSuppressed(
                "tenant-a",
                LearningArtifactTypeNames.DECISION_QUALITY_PROFILE,
                "profile/new-device-post-mfa-sensitive")).isTrue();
        assertThat(ledgerService.latest(
                "tenant-a",
                LearningArtifactTypeNames.DECISION_QUALITY_PROFILE,
                "profile/new-device-post-mfa-sensitive"))
                .hasValueSatisfying(entry -> {
                    assertThat(entry.releaseState()).isEqualTo(LearningArtifactReleaseState.REVIEW_ONLY);
                    assertThat(entry.rollbackTargetState()).isEqualTo(LearningArtifactReleaseState.REVIEW_ONLY);
                    assertThat(entry.reason()).contains("Local truth overrode promoted decision-quality profile");
                });
    }

    @Test
    void doesNotDuplicateReviewOnlyConflictWhenLatestStateAlreadySuppressesRuntime() {
        runtimeConflictService.recordReviewOnlyConflict(
                "tenant-a",
                LearningArtifactTypeNames.DETECTION_STRATEGY,
                "strategy/path-sequence-divergence",
                "2026.04.08-v1",
                null,
                List.of("strategyFamily=PATH_SEQUENCE_DIVERGENCE"));

        boolean recordedAgain = runtimeConflictService.recordReviewOnlyConflict(
                "tenant-a",
                LearningArtifactTypeNames.DETECTION_STRATEGY,
                "strategy/path-sequence-divergence",
                "2026.04.08-v1",
                null,
                List.of("strategyFamily=PATH_SEQUENCE_DIVERGENCE"));

        assertThat(recordedAgain).isFalse();
        assertThat(ledgerService.history(
                "tenant-a",
                LearningArtifactTypeNames.DETECTION_STRATEGY,
                "strategy/path-sequence-divergence",
                10)).hasSize(1);
    }
}