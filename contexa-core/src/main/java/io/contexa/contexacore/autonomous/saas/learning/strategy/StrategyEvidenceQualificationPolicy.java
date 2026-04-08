package io.contexa.contexacore.autonomous.saas.learning.strategy;

/**
 * Policy contract that decides whether a strategy family has enough evidence to become an artifact candidate.
 */
public interface StrategyEvidenceQualificationPolicy {

    StrategyEvidenceQualificationDecision evaluate(DetectionStrategyLearningFamilyResult familyResult);
}
