package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyPackCandidate;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;

import java.util.List;

/**
 * Final strategy pipeline output for orchestration and registry ingestion.
 */
public record DetectionStrategyArtifactPipelineResult(
        DetectionStrategyLearningPortfolio learningPortfolio,
        List<DetectionStrategyPackCandidate> candidates,
        ArtifactTransferRiskAssessment transferRiskAssessment,
        DetectionStrategyPackSnapshot snapshot,
        DetectionStrategyRuntimePack runtimePack) {

    public DetectionStrategyArtifactPipelineResult {
        learningPortfolio = learningPortfolio == null ? DetectionStrategyLearningPortfolio.empty() : learningPortfolio;
        candidates = candidates == null ? List.of() : List.copyOf(candidates);
    }
}