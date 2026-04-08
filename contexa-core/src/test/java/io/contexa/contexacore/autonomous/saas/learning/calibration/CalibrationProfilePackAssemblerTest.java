package io.contexa.contexacore.autonomous.saas.learning.calibration;

import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CalibrationProfilePackAssemblerTest {

    private final CalibrationProfilePackAssembler assembler = new CalibrationProfilePackAssembler();

    @Test
    void assemblesSnapshotAndRuntimePack() {
        LearningArtifactMetadata metadata = new LearningArtifactMetadata(
                LearningArtifactReleaseState.PROMOTED,
                new LearningArtifactMetrics(12L, 0.75d, 0.20d, 0.10d, -0.04d, 0.03d),
                List.of(new LearningArtifactGuardrail("bias-reviewed", "Bias risk reviewed", true)));
        CalibrationProfilePackCandidate candidate = new CalibrationProfilePackCandidate(
                new CalibrationProfileLearningScenarioResult(
                        "SESSION_PATH_SIMILARITY_BREAK",
                        new DecisionBiasAggregationResult(12L, 10L, 2L, 1L, 0.20d, 0.10d, 0.25d, 0.10d, -0.05d, "DECREASE_CHALLENGE", List.of("aggregated")),
                        List.of("evidence")),
                metadata,
                List.of("policy"));

        CalibrationProfilePackSnapshot snapshot = assembler.assembleSnapshot("tenant-a", true, true, List.of(candidate));
        CalibrationProfileRuntimePack runtimePack = assembler.assembleRuntimePack("tenant-a", List.of(candidate));

        assertThat(snapshot.runtimeReady()).isTrue();
        assertThat(snapshot.promotedProfileCount()).isEqualTo(1L);
        assertThat(snapshot.profiles()).hasSize(1);
        assertThat(snapshot.profiles().get(0).profileKey()).isEqualTo("calibration-profile/session-path-similarity-break");
        assertThat(snapshot.profiles().get(0).recommendedActionBias()).isEqualTo("DECREASE_CHALLENGE");
        assertThat(runtimePack.runtimeReady()).isTrue();
        assertThat(runtimePack.profiles()).hasSize(1);
        assertThat(runtimePack.profiles().get(0).metadata().releaseState()).isEqualTo(LearningArtifactReleaseState.PROMOTED);
    }
}
