package io.contexa.contexacore.autonomous.saas.learning.quality;

/**
 * Policy contract that decides whether a scenario-level decision-quality result can become an artifact candidate.
 */
public interface DecisionQualityQualificationPolicy {

    DecisionQualityQualificationDecision evaluate(DecisionQualityScenarioResult scenarioResult);
}