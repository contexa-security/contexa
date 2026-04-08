package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionStrategyPackAssemblerTest {

    private final DetectionStrategyPackAssembler assembler = new DetectionStrategyPackAssembler();
    private final StrategyEvidenceQualificationThresholds thresholds = new StrategyEvidenceQualificationThresholds(8L, 0.60d, 0.10d, 0.05d);

    @Test
    void assemblesSnapshotForQualifiedCandidate() {
        DetectionStrategyPackCandidate candidate = new DetectionStrategyPackCandidate(
                familyResult("PATH_SEQUENCE_DIVERGENCE", new LearningArtifactMetrics(12L, 0.82d, 0.18d, 0.11d, 0.02d, -0.03d)),
                new StrategyEvidenceQualificationDecision(true, LearningArtifactReleaseState.SHADOW_READY, List.of(), List.of("qualified")),
                thresholds);

        DetectionStrategyPackSnapshot snapshot = assembler.assembleSnapshot("tenant-a", true, true, List.of(candidate));

        assertThat(snapshot.tenantId()).isEqualTo("tenant-a");
        assertThat(snapshot.featureEnabled()).isTrue();
        assertThat(snapshot.sharingEnabled()).isTrue();
        assertThat(snapshot.runtimeReady()).isFalse();
        assertThat(snapshot.promotionState()).isEqualTo("SHADOW_READY");
        assertThat(snapshot.promotedStrategyCount()).isZero();
        assertThat(snapshot.candidateStrategyCount()).isEqualTo(1L);
        assertThat(snapshot.collectingStrategyCount()).isZero();
        assertThat(snapshot.strategies()).hasSize(1);
        assertThat(snapshot.strategies().get(0).strategyKey()).isEqualTo("detection-strategy/path-sequence-divergence");
        assertThat(snapshot.strategies().get(0).confidenceBand()).isEqualTo("HIGH");
        assertThat(snapshot.strategies().get(0).requiredSignals()).contains("requestPath", "previousPath", "signalKeys");
    }

    @Test
    void assemblesCollectingSnapshotWithGuardrailsWhenCandidateIsUnqualified() {
        DetectionStrategyPackCandidate candidate = new DetectionStrategyPackCandidate(
                familyResult("INITIAL_REQUEST_PROFILE_DELTA", new LearningArtifactMetrics(12L, 0.42d, 0.05d, 0.01d, 0.04d, -0.01d)),
                new StrategyEvidenceQualificationDecision(
                        false,
                        LearningArtifactReleaseState.COLLECTING,
                        List.of("Outcome coverage 0.4200 is below the minimum outcome coverage floor 0.6000."),
                        List.of("blocked")),
                thresholds);

        DetectionStrategyPackSnapshot snapshot = assembler.assembleSnapshot("tenant-b", true, true, List.of(candidate));
        DetectionStrategyRuntimePack runtimePack = assembler.assembleRuntimePack("tenant-b", List.of(candidate));

        assertThat(snapshot.promotionState()).isEqualTo("COLLECTING");
        assertThat(snapshot.collectingStrategyCount()).isEqualTo(1L);
        assertThat(snapshot.strategies().get(0).guardrails()).containsExactly("Outcome coverage 0.4200 is below the minimum outcome coverage floor 0.6000.");
        assertThat(runtimePack.runtimeReady()).isFalse();
        assertThat(runtimePack.strategies()).hasSize(1);
        assertThat(runtimePack.strategies().get(0).metadata().releaseState()).isEqualTo(LearningArtifactReleaseState.COLLECTING);
        assertThat(runtimePack.strategies().get(0).metadata().hasBlockingGuardrails()).isTrue();
    }

    private DetectionStrategyLearningFamilyResult familyResult(String family, LearningArtifactMetrics metrics) {
        return new DetectionStrategyLearningFamilyResult(
                family,
                metrics,
                10L,
                2L,
                4L,
                1L,
                0L,
                5L,
                6L,
                1L,
                List.of("evidence fact"));
    }
}
