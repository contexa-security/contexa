package io.contexa.contexacore.autonomous.saas.learning.sanitization;

import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningScenarioResult;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningFamilyResult;

/**
 * Central sanitization facade for cross-tenant learning artifact evidence.
 */
public class LearningArtifactSanitizationService {

    private final DetectionStrategyEvidenceSanitizer strategyEvidenceSanitizer;
    private final CalibrationEvidenceSanitizer calibrationEvidenceSanitizer;

    public LearningArtifactSanitizationService(
            DetectionStrategyEvidenceSanitizer strategyEvidenceSanitizer,
            CalibrationEvidenceSanitizer calibrationEvidenceSanitizer) {
        this.strategyEvidenceSanitizer = strategyEvidenceSanitizer;
        this.calibrationEvidenceSanitizer = calibrationEvidenceSanitizer;
    }

    public DetectionStrategyLearningFamilyResult sanitize(DetectionStrategyLearningFamilyResult result) {
        if (result == null) {
            return null;
        }
        return new DetectionStrategyLearningFamilyResult(
                result.strategyFamily(),
                result.metrics(),
                result.outcomeEvidenceCount(),
                result.hardNegativeCount(),
                result.confirmedAttackCount(),
                result.falsePositiveCount(),
                result.falseNegativeCount(),
                result.promptAuditLinkedCount(),
                result.telemetryLinkedCount(),
                result.campaignObservationCount(),
                strategyEvidenceSanitizer.sanitize(result.evidenceFacts()));
    }

    public CalibrationProfileLearningScenarioResult sanitize(CalibrationProfileLearningScenarioResult result) {
        if (result == null) {
            return null;
        }
        return new CalibrationProfileLearningScenarioResult(
                result.scenarioClass(),
                result.biasAggregation(),
                calibrationEvidenceSanitizer.sanitize(result.evidenceFacts()));
    }
}