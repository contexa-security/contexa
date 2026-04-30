package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LearningArtifactReleaseLedgerServiceTest {

    private final LearningArtifactReleaseLedgerService service =
            new LearningArtifactReleaseLedgerService(new InMemoryLearningArtifactReleaseLedgerStore());

    @Test
    @DisplayName("release ledger should persist creation, canary, rollback, withdraw, and kill-switch history")
    void shouldPersistRequiredHistory() {
        service.recordArtifactCreated("tenant-acme", "DETECTION_STRATEGY", "strategy-1", "v1", "system", "created", LearningArtifactReleaseState.COLLECTING, List.of("created"));
        service.recordCanaryResult("tenant-acme", "DETECTION_STRATEGY", "strategy-1", "v1", "operator", "canary ok", LearningArtifactReleaseState.CANARY_READY, "CANARY_READY", "POSITIVE_SHIFT", List.of("canary"));
        service.recordRollback("tenant-acme", "DETECTION_STRATEGY", "strategy-1", "v1", "operator", "rollback", LearningArtifactReleaseState.PROMOTED, LearningArtifactReleaseState.REVIEW_ONLY, List.of("rollback"));
        service.recordWithdrawn("tenant-acme", "DETECTION_STRATEGY", "strategy-1", "v1", "operator", "withdrawn by operator", List.of("withdrawn"));
        service.recordKillSwitchActivated("tenant-acme", "DETECTION_STRATEGY", "strategy-1", "v1", "operator", "kill switch", List.of("kill-switch"));

        List<LearningArtifactReleaseLedgerEntry> history = service.history("tenant-acme", "DETECTION_STRATEGY", "strategy-1", 10);

        assertThat(history).hasSize(5);
        assertThat(history).extracting(LearningArtifactReleaseLedgerEntry::eventType)
                .contains(
                        LearningArtifactReleaseLedgerEventType.ARTIFACT_CREATED,
                        LearningArtifactReleaseLedgerEventType.CANARY_RESULT_RECORDED,
                        LearningArtifactReleaseLedgerEventType.ROLLBACK_RECORDED,
                        LearningArtifactReleaseLedgerEventType.WITHDRAWN,
                        LearningArtifactReleaseLedgerEventType.KILL_SWITCH_ACTIVATED);
        assertThat(history).anyMatch(entry -> "withdrawn by operator".equals(entry.reason()));
        assertThat(history).anyMatch(entry -> entry.killSwitchActive() && entry.eventType() == LearningArtifactReleaseLedgerEventType.KILL_SWITCH_ACTIVATED);
        assertThat(history).anyMatch(entry -> entry.rollbackTargetState() == LearningArtifactReleaseState.REVIEW_ONLY);
        assertThat(history).anyMatch(entry -> "POSITIVE_SHIFT".equals(entry.canaryOutcome()));
    }

    @Test
    @DisplayName("latest should return the newest ledger entry for the artifact")
    void shouldReturnLatestEntry() {
        service.recordArtifactCreated("tenant-acme", "DECISION_QUALITY_PROFILE", "profile-1", "v2", "system", "created", LearningArtifactReleaseState.COLLECTING, List.of());
        LearningArtifactReleaseLedgerEntry latest = service.recordKillSwitchCleared(
                "tenant-acme",
                "DECISION_QUALITY_PROFILE",
                "profile-1",
                "v2",
                "operator",
                "cleared",
                LearningArtifactReleaseState.REVIEW_ONLY,
                "REVIEW_ONLY",
                List.of("cleared"));

        assertThat(service.latest("tenant-acme", "DECISION_QUALITY_PROFILE", "profile-1"))
                .contains(latest);
    }
}
