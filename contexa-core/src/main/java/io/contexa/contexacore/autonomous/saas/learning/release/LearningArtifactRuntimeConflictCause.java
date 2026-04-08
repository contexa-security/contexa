package io.contexa.contexacore.autonomous.saas.learning.release;
/**
 * Primary cause for a runtime conflict between local truth and a SaaS learning artifact.
 */
public enum LearningArtifactRuntimeConflictCause {
    NONE,
    LOCAL_TRUTH_OVERRIDE,
    LOW_EVIDENCE_RUNTIME_MISMATCH,
    HIGH_FALSE_POSITIVE_REGRESSION,
    OPERATOR_REVIEW_REGRESSION,
    PROMPT_BIAS_RISK,
    COHORT_OVERREACH,
    REPEATED_RUNTIME_CONFLICT
}
