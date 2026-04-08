package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;

import java.util.List;

/**
 * Strategy-family effectiveness result emitted by the learning engine.
 */
public record DetectionStrategyLearningFamilyResult(
        String strategyFamily,
        LearningArtifactMetrics metrics,
        long outcomeEvidenceCount,
        long hardNegativeCount,
        long confirmedAttackCount,
        long falsePositiveCount,
        long falseNegativeCount,
        long promptAuditLinkedCount,
        long telemetryLinkedCount,
        long campaignObservationCount,
        List<String> evidenceFacts) {

    public DetectionStrategyLearningFamilyResult {
        strategyFamily = strategyFamily == null ? "UNCLASSIFIED" : strategyFamily.trim();
        metrics = metrics == null ? LearningArtifactMetrics.empty() : metrics;
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
