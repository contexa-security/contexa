package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.util.List;

/**
 * Correlates raw feedback, outcome, prompt, telemetry, and campaign inputs.
 */
public interface StrategyOutcomeJoinService {

    List<StrategyLearningObservation> join(DetectionStrategyLearningInput input);
}
