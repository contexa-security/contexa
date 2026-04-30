package io.contexa.contexacore.autonomous.saas.learning.quality;

/**
 * Resolves a stable scenario class from a correlated observation.
 */
public interface ScenarioClassResolver {

    ScenarioClassResolution resolve(DecisionQualityObservation observation);
}
