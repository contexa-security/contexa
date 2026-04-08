package io.contexa.contexacore.autonomous.saas.learning.calibration;

/**
 * Default evidence floors for calibration profile artifact qualification.
 */
public record CalibrationProfileQualificationThresholds(
        long minimumSampleSize,
        long minimumReviewedOutcomeCount,
        double maximumFalsePositiveRate,
        double maximumFalseNegativeRate) {

    public CalibrationProfileQualificationThresholds {
        if (minimumSampleSize < 0L) {
            throw new IllegalArgumentException("minimumSampleSize must be >= 0");
        }
        if (minimumReviewedOutcomeCount < 0L) {
            throw new IllegalArgumentException("minimumReviewedOutcomeCount must be >= 0");
        }
        maximumFalsePositiveRate = requireFinite(maximumFalsePositiveRate, "maximumFalsePositiveRate");
        maximumFalseNegativeRate = requireFinite(maximumFalseNegativeRate, "maximumFalseNegativeRate");
    }

    public static CalibrationProfileQualificationThresholds defaults() {
        return new CalibrationProfileQualificationThresholds(25L, 10L, 0.35d, 0.35d);
    }

    private static double requireFinite(double value, String fieldName) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(fieldName + " must be finite");
        }
        return value;
    }
}