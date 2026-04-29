package io.contexa.contexacore.autonomous.saas.learning.quality;

/**
 * Default evidence floors for decision-quality profile artifact qualification.
 */
public record DecisionQualityQualificationThresholds(
        long minimumSampleSize,
        long minimumReviewedOutcomeCount,
        double maximumFalsePositiveRate,
        double maximumFalseNegativeRate) {

    public DecisionQualityQualificationThresholds {
        if (minimumSampleSize < 0L) {
            throw new IllegalArgumentException("minimumSampleSize must be >= 0");
        }
        if (minimumReviewedOutcomeCount < 0L) {
            throw new IllegalArgumentException("minimumReviewedOutcomeCount must be >= 0");
        }
        maximumFalsePositiveRate = requireFinite(maximumFalsePositiveRate, "maximumFalsePositiveRate");
        maximumFalseNegativeRate = requireFinite(maximumFalseNegativeRate, "maximumFalseNegativeRate");
    }

    public static DecisionQualityQualificationThresholds defaults() {
        return new DecisionQualityQualificationThresholds(25L, 10L, 0.35d, 0.35d);
    }

    private static double requireFinite(double value, String fieldName) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(fieldName + " must be finite");
        }
        return value;
    }
}