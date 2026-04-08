package io.contexa.contexacore.autonomous.saas.learning.strategy;

/**
 * Resolves a strategy family for a correlated learning observation.
 */
public interface StrategyFamilyResolver {

    StrategyFamilyResolution resolve(StrategyLearningObservation observation);
}
