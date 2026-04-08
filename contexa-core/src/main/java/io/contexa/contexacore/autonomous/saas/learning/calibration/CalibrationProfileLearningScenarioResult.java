package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.util.List;

/**
 * Learned scenario-level calibration result.
 */
public record CalibrationProfileLearningScenarioResult(
        String scenarioClass,
        DecisionBiasAggregationResult biasAggregation,
        List<String> evidenceFacts) {

    public CalibrationProfileLearningScenarioResult {
        scenarioClass = scenarioClass == null ? null : scenarioClass.trim();
        biasAggregation = biasAggregation == null ? DecisionBiasAggregationResult.empty() : biasAggregation;
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
