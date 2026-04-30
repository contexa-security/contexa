package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.dto.DecisionQualityProfileSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityProfileCandidate;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;

import java.util.List;

/**
 * Final decision-quality pipeline output for orchestration and registry ingestion.
 */
public record DecisionQualityArtifactPipelineResult(
        DecisionQualityLearningPortfolio learningPortfolio,
        List<DecisionQualityProfileCandidate> candidates,
        ArtifactTransferRiskAssessment transferRiskAssessment,
        DecisionQualityProfileSnapshot snapshot) {

    public DecisionQualityArtifactPipelineResult {
        learningPortfolio = learningPortfolio == null ? DecisionQualityLearningPortfolio.empty() : learningPortfolio;
        candidates = candidates == null ? List.of() : List.copyOf(candidates);
    }
}
