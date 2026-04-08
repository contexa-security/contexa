package io.contexa.contexacore.autonomous.saas.learning.calibration;

/**
 * Policy contract that decides whether a scenario-level calibration result can become an artifact candidate.
 */
public interface CalibrationProfileQualificationPolicy {

    CalibrationProfileQualificationDecision evaluate(CalibrationProfileLearningScenarioResult scenarioResult);
}