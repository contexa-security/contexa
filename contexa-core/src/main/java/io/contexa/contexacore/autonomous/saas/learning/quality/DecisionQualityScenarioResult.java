package io.contexa.contexacore.autonomous.saas.learning.quality;

import java.util.List;

/**
 * Learned scenario-level decision-quality result.
 */
public record DecisionQualityScenarioResult(
        String scenarioClass,
        DecisionBiasAggregationResult biasAggregation,
        List<String> evidenceFacts) {

    public DecisionQualityScenarioResult {
        scenarioClass = scenarioClass == null ? null : scenarioClass.trim();
        biasAggregation = biasAggregation == null ? DecisionBiasAggregationResult.empty() : biasAggregation;
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
