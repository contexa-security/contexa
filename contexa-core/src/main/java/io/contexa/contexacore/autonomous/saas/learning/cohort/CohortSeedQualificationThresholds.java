package io.contexa.contexacore.autonomous.saas.learning.cohort;

/**
 * Thresholds for cohort seed qualification.
 */
public record CohortSeedQualificationThresholds(
        int minimumCohortTenantCount,
        long minimumSampleUserBaselineCount,
        long minimumEarlyAssessmentSampleCount,
        double minimumEarlyQualityImprovementDelta,
        int strongCohortTenantCount,
        long strongSampleUserBaselineCount,
        double strongEarlyQualityImprovementDelta) {

    public CohortSeedQualificationThresholds {
        if (minimumCohortTenantCount < 0) {
            throw new IllegalArgumentException("minimumCohortTenantCount must be >= 0");
        }
        if (minimumSampleUserBaselineCount < 0L) {
            throw new IllegalArgumentException("minimumSampleUserBaselineCount must be >= 0");
        }
        if (minimumEarlyAssessmentSampleCount < 0L) {
            throw new IllegalArgumentException("minimumEarlyAssessmentSampleCount must be >= 0");
        }
        if (!Double.isFinite(minimumEarlyQualityImprovementDelta)) {
            throw new IllegalArgumentException("minimumEarlyQualityImprovementDelta must be finite");
        }
        if (strongCohortTenantCount < minimumCohortTenantCount) {
            throw new IllegalArgumentException("strongCohortTenantCount must be >= minimumCohortTenantCount");
        }
        if (strongSampleUserBaselineCount < minimumSampleUserBaselineCount) {
            throw new IllegalArgumentException("strongSampleUserBaselineCount must be >= minimumSampleUserBaselineCount");
        }
        if (!Double.isFinite(strongEarlyQualityImprovementDelta)
                || strongEarlyQualityImprovementDelta < minimumEarlyQualityImprovementDelta) {
            throw new IllegalArgumentException("strongEarlyQualityImprovementDelta must be finite and >= minimumEarlyQualityImprovementDelta");
        }
    }

    public static CohortSeedQualificationThresholds defaults() {
        return new CohortSeedQualificationThresholds(5, 100L, 20L, 5.0d, 12, 250L, 10.0d);
    }
}