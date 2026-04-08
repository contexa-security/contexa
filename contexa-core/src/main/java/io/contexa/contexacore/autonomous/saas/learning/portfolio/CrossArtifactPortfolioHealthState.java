package io.contexa.contexacore.autonomous.saas.learning.portfolio;
/**
 * Portfolio health state across strategy, calibration, prompt, and cohort artifacts.
 */
public enum CrossArtifactPortfolioHealthState {
    EMPTY,
    COHORT_ONLY,
    STRATEGY_ONLY,
    CALIBRATION_WITHOUT_STRATEGY,
    PROMPT_WITHOUT_CORE,
    BALANCED
}
