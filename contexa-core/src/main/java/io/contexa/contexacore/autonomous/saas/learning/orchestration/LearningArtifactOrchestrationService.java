package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityLearningInput;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningInput;

/**
 * Top-level orchestration facade for strategy and decision-quality artifact generation.
 */
public class LearningArtifactOrchestrationService {

    private final DetectionStrategyArtifactPipeline detectionStrategyArtifactPipeline;
    private final DecisionQualityArtifactPipeline decisionQualityArtifactPipeline;

    public LearningArtifactOrchestrationService(
            DetectionStrategyArtifactPipeline detectionStrategyArtifactPipeline,
            DecisionQualityArtifactPipeline decisionQualityArtifactPipeline) {
        this.detectionStrategyArtifactPipeline = detectionStrategyArtifactPipeline;
        this.decisionQualityArtifactPipeline = decisionQualityArtifactPipeline;
    }

    public DetectionStrategyArtifactPipelineResult orchestrateDetectionStrategies(
            String tenantId,
            DetectionStrategyLearningInput input) {
        return detectionStrategyArtifactPipeline.execute(tenantId, input);
    }

    public DecisionQualityArtifactPipelineResult orchestrateDecisionQualityProfiles(
            String tenantId,
            DecisionQualityLearningInput input) {
        return decisionQualityArtifactPipeline.execute(tenantId, input);
    }
}