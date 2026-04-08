package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.SaasCalibrationProfilePackService;
import io.contexa.contexacore.autonomous.saas.SaasDetectionStrategyPackService;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Coordinates runtime cache invalidation and refresh for governed learning artifacts.
 */
public class LearningArtifactRuntimeRefreshService {

    private final SaasDetectionStrategyPackService detectionStrategyPackService;
    private final SaasCalibrationProfilePackService calibrationProfilePackService;

    public LearningArtifactRuntimeRefreshService(
            SaasDetectionStrategyPackService detectionStrategyPackService,
            SaasCalibrationProfilePackService calibrationProfilePackService) {
        this.detectionStrategyPackService = detectionStrategyPackService;
        this.calibrationProfilePackService = calibrationProfilePackService;
    }

    public LearningArtifactRuntimeRefreshResult refreshArtifact(String artifactType) {
        String safeArtifactType = artifactType == null ? "UNKNOWN" : artifactType.trim().toUpperCase(Locale.ROOT);
        return switch (safeArtifactType) {
            case LearningArtifactTypeNames.DETECTION_STRATEGY -> refreshDetectionStrategy();
            case LearningArtifactTypeNames.CALIBRATION_PROFILE -> refreshCalibrationProfile();
            case LearningArtifactTypeNames.PROMPT_PRESENTATION, LearningArtifactTypeNames.COHORT_SEED ->
                    new LearningArtifactRuntimeRefreshResult(
                            safeArtifactType,
                            false,
                            false,
                            false,
                            List.of("Runtime refresh is not applicable to governance-only artifacts in P0."));
            default -> new LearningArtifactRuntimeRefreshResult(
                    safeArtifactType,
                    false,
                    false,
                    false,
                    List.of("Unknown learning artifact type; runtime refresh was skipped."));
        };
    }

    private LearningArtifactRuntimeRefreshResult refreshDetectionStrategy() {
        List<String> facts = new ArrayList<>();
        if (detectionStrategyPackService == null) {
            facts.add("Detection strategy runtime service is not configured.");
            return new LearningArtifactRuntimeRefreshResult(LearningArtifactTypeNames.DETECTION_STRATEGY, false, false, false, facts);
        }
        detectionStrategyPackService.invalidateAndRefresh();
        facts.add("Detection strategy runtime cache invalidated.");
        facts.add("Detection strategy runtime snapshot refreshed.");
        return new LearningArtifactRuntimeRefreshResult(LearningArtifactTypeNames.DETECTION_STRATEGY, true, true, true, facts);
    }

    private LearningArtifactRuntimeRefreshResult refreshCalibrationProfile() {
        List<String> facts = new ArrayList<>();
        if (calibrationProfilePackService == null) {
            facts.add("Calibration profile runtime service is not configured.");
            return new LearningArtifactRuntimeRefreshResult(LearningArtifactTypeNames.CALIBRATION_PROFILE, false, false, false, facts);
        }
        calibrationProfilePackService.invalidateAndRefresh();
        facts.add("Calibration profile runtime cache invalidated.");
        facts.add("Calibration profile runtime snapshot refreshed.");
        return new LearningArtifactRuntimeRefreshResult(LearningArtifactTypeNames.CALIBRATION_PROFILE, true, true, true, facts);
    }
}