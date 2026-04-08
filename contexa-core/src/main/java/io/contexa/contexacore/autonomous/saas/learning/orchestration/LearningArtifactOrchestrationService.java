package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningInput;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningInput;

/**
 * Top-level orchestration facade for strategy and calibration artifact generation.
 */
public class LearningArtifactOrchestrationService {

    private final DetectionStrategyArtifactPipeline detectionStrategyArtifactPipeline;
    private final CalibrationProfileArtifactPipeline calibrationProfileArtifactPipeline;

    public LearningArtifactOrchestrationService(
            DetectionStrategyArtifactPipeline detectionStrategyArtifactPipeline,
            CalibrationProfileArtifactPipeline calibrationProfileArtifactPipeline) {
        this.detectionStrategyArtifactPipeline = detectionStrategyArtifactPipeline;
        this.calibrationProfileArtifactPipeline = calibrationProfileArtifactPipeline;
    }

    public DetectionStrategyArtifactPipelineResult orchestrateDetectionStrategies(
            String tenantId,
            DetectionStrategyLearningInput input) {
        return detectionStrategyArtifactPipeline.execute(tenantId, input);
    }

    public CalibrationProfileArtifactPipelineResult orchestrateCalibrationProfiles(
            String tenantId,
            CalibrationProfileLearningInput input) {
        return calibrationProfileArtifactPipeline.execute(tenantId, input);
    }
}