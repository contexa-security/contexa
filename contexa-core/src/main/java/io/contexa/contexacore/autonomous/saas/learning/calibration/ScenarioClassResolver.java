package io.contexa.contexacore.autonomous.saas.learning.calibration;

/**
 * Resolves a stable scenario class from a correlated observation.
 */
public interface ScenarioClassResolver {

    ScenarioClassResolution resolve(CalibrationLearningObservation observation);
}
