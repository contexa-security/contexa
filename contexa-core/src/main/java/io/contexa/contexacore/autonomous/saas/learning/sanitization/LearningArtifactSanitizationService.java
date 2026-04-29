package io.contexa.contexacore.autonomous.saas.learning.sanitization;

import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityScenarioResult;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningFamilyResult;

/**
 * Central sanitization facade for cross-tenant learning artifact evidence.
 */
public class LearningArtifactSanitizationService {

    private final DetectionStrategyEvidenceSanitizer strategyEvidenceSanitizer;
    private final DecisionQualityEvidenceSanitizer decisionQualityEvidenceSanitizer;

    public LearningArtifactSanitizationService(
            DetectionStrategyEvidenceSanitizer strategyEvidenceSanitizer,
            DecisionQualityEvidenceSanitizer decisionQualityEvidenceSanitizer) {
        this.strategyEvidenceSanitizer = strategyEvidenceSanitizer;
        this.decisionQualityEvidenceSanitizer = decisionQualityEvidenceSanitizer;
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

    public DecisionQualityScenarioResult sanitize(DecisionQualityScenarioResult result) {
        if (result == null) {
            return null;
        }
        return new DecisionQualityScenarioResult(
                result.scenarioClass(),
                result.biasAggregation(),
                decisionQualityEvidenceSanitizer.sanitize(result.evidenceFacts()));
    }
}
