package io.contexa.contexacore.autonomous.saas.learning;

/**
 * Shared quantitative metrics for learning artifacts.
 */
public record LearningArtifactMetrics(
        long sampleSize,
        double outcomeCoverageRate,
        double hardNegativeCoverage,
        double localLiftRate,
        double fpDelta,
        double fnDelta) {

    public LearningArtifactMetrics {
        if (sampleSize < 0) {
            throw new IllegalArgumentException("sampleSize must be zero or greater");
        }
        validateRate("outcomeCoverageRate", outcomeCoverageRate);
        validateRate("hardNegativeCoverage", hardNegativeCoverage);
        validateFinite("localLiftRate", localLiftRate);
        validateFinite("fpDelta", fpDelta);
        validateFinite("fnDelta", fnDelta);
    }

    public static LearningArtifactMetrics empty() {
        return new LearningArtifactMetrics(0, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d);
    }

    public boolean hasEvidence() {
        return sampleSize > 0;
    }

    public boolean hasCoverage() {
        return outcomeCoverageRate > 0.0d || hardNegativeCoverage > 0.0d;
    }

    private static void validateRate(String fieldName, double value) {
        validateFinite(fieldName, value);
        if (value < 0.0d || value > 1.0d) {
            throw new IllegalArgumentException(fieldName + " must be between 0.0 and 1.0");
        }
    }

    private static void validateFinite(String fieldName, double value) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(fieldName + " must be finite");
        }
    }
}
