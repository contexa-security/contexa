package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;

/**
 * Input for cohort-seed qualification.
 */
public record CohortSeedQualificationInput(
        BaselineSeedSnapshot baselineSeedSnapshot,
        long earlyAssessmentSampleCount,
        double earlyQualityImprovementDelta) {

    public CohortSeedQualificationInput {
        earlyAssessmentSampleCount = Math.max(earlyAssessmentSampleCount, 0L);
        earlyQualityImprovementDelta = Double.isFinite(earlyQualityImprovementDelta) ? earlyQualityImprovementDelta : 0.0d;
    }
}