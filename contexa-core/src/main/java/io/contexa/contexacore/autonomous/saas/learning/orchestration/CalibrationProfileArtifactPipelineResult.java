package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfilePackCandidate;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;

import java.util.List;

/**
 * Final calibration pipeline output for orchestration and registry ingestion.
 */
public record CalibrationProfileArtifactPipelineResult(
        CalibrationProfileLearningPortfolio learningPortfolio,
        List<CalibrationProfilePackCandidate> candidates,
        ArtifactTransferRiskAssessment transferRiskAssessment,
        CalibrationProfilePackSnapshot snapshot,
        CalibrationProfileRuntimePack runtimePack) {

    public CalibrationProfileArtifactPipelineResult {
        learningPortfolio = learningPortfolio == null ? CalibrationProfileLearningPortfolio.empty() : learningPortfolio;
        candidates = candidates == null ? List.of() : List.copyOf(candidates);
    }
}