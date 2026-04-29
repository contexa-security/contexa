package io.contexa.contexacore.autonomous.saas.learning.quality;

import java.util.List;

/**
 * Aggregates scenario-class bias from resolved observations.
 */
public interface DecisionBiasAggregator {

    DecisionBiasAggregationResult aggregate(String scenarioClass, List<DecisionQualityObservation> observations);
}
