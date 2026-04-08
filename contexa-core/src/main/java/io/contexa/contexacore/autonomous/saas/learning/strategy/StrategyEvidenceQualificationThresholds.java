package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.util.Objects;

/**
 * Qualification floors that a detection strategy family must satisfy before artifact promotion.
 */
public record StrategyEvidenceQualificationThresholds(
        long minimumEvidenceCount,
        double minimumOutcomeCoverageRate,
        double minimumHardNegativeCoverageRate,
        double minimumLocalLiftRate) {

    public StrategyEvidenceQualificationThresholds {
        if (minimumEvidenceCount < 0L) {
            throw new IllegalArgumentException("minimumEvidenceCount must be >= 0");
        }
        validateRate("minimumOutcomeCoverageRate", minimumOutcomeCoverageRate);
        validateRate("minimumHardNegativeCoverageRate", minimumHardNegativeCoverageRate);
        if (!Double.isFinite(minimumLocalLiftRate)) {
            throw new IllegalArgumentException("minimumLocalLiftRate must be finite");
        }
    }

    public static StrategyEvidenceQualificationThresholds defaults() {
        return new StrategyEvidenceQualificationThresholds(25L, 0.60d, 0.05d, 0.03d);
    }

    private static void validateRate(String fieldName, double value) {
        if (!Double.isFinite(value) || value < 0.0d || value > 1.0d) {
            throw new IllegalArgumentException(fieldName + " must be between 0.0 and 1.0");
        }
    }
}
