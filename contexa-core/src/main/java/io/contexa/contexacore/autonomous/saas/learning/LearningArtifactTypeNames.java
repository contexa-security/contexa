package io.contexa.contexacore.autonomous.saas.learning;
/**
 * Canonical artifact type names shared across runtime policy, ledger, and runtime suppression.
 */
public final class LearningArtifactTypeNames {
    public static final String DETECTION_STRATEGY = "DETECTION_STRATEGY";
    public static final String CALIBRATION_PROFILE = "CALIBRATION_PROFILE";
    public static final String PROMPT_PRESENTATION = "PROMPT_PRESENTATION";
    public static final String COHORT_SEED = "COHORT_SEED";
    private LearningArtifactTypeNames() {
        throw new IllegalStateException("Utility class");
    }
}
