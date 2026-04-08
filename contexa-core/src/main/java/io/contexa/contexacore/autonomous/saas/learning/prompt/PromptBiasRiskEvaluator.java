package io.contexa.contexacore.autonomous.saas.learning.prompt;

/**
 * Evaluates semantic-bias risk for a prompt presentation experiment result.
 */
public interface PromptBiasRiskEvaluator {

    PromptBiasRiskAssessment evaluate(PromptPresentationExperimentResult result);
}