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
