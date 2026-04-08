package io.contexa.contexacore.autonomous.saas.learning.release;
/**
 * Thresholds used by runtime conflict remediation policy.
 */
public record LearningArtifactRuntimeConflictThresholds(
        double reviewOnlyEvidenceCoverageFloor,
        double withdrawFalsePositiveRateThreshold,
        int withdrawRepeatedConflictCount,
        int withdrawOperatorRegressionCount) {
    public LearningArtifactRuntimeConflictThresholds {
        if (!Double.isFinite(reviewOnlyEvidenceCoverageFloor) || reviewOnlyEvidenceCoverageFloor < 0.0d || reviewOnlyEvidenceCoverageFloor > 1.0d) {
            throw new IllegalArgumentException("reviewOnlyEvidenceCoverageFloor must be between 0.0 and 1.0");
        }
        if (!Double.isFinite(withdrawFalsePositiveRateThreshold) || withdrawFalsePositiveRateThreshold < 0.0d || withdrawFalsePositiveRateThreshold > 1.0d) {
            throw new IllegalArgumentException("withdrawFalsePositiveRateThreshold must be between 0.0 and 1.0");
        }
        if (withdrawRepeatedConflictCount < 1) {
            throw new IllegalArgumentException("withdrawRepeatedConflictCount must be at least 1");
        }
        if (withdrawOperatorRegressionCount < 1) {
            throw new IllegalArgumentException("withdrawOperatorRegressionCount must be at least 1");
        }
    }
    public static LearningArtifactRuntimeConflictThresholds defaults() {
        return new LearningArtifactRuntimeConflictThresholds(0.50d, 0.20d, 3, 3);
    }
}
