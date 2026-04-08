package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;

import java.util.Map;

/**
 * Input for cohort seed expansion.
 */
public record CohortSeedExpansionInput(
        BaselineSeedSnapshot baselineSeedSnapshot,
        CohortSeedQualificationDecision qualificationDecision,
        String sizeBand,
        long earlyAssessmentSampleCount,
        double earlyQualityImprovementDelta,
        Map<String, Long> firstSequenceFamilyDistribution,
        Map<String, Long> sessionLengthBandDistribution,
        Map<String, Long> surfaceTransitionPriorDistribution) {

    public CohortSeedExpansionInput {
        qualificationDecision = qualificationDecision == null
                ? new CohortSeedQualificationDecision(false, CohortSeedSupportLevel.INSUFFICIENT, null, java.util.List.of(), java.util.List.of())
                : qualificationDecision;
        sizeBand = normalize(sizeBand);
        earlyAssessmentSampleCount = Math.max(earlyAssessmentSampleCount, 0L);
        earlyQualityImprovementDelta = Double.isFinite(earlyQualityImprovementDelta) ? earlyQualityImprovementDelta : 0.0d;
        firstSequenceFamilyDistribution = firstSequenceFamilyDistribution == null ? Map.of() : Map.copyOf(firstSequenceFamilyDistribution);
        sessionLengthBandDistribution = sessionLengthBandDistribution == null ? Map.of() : Map.copyOf(sessionLengthBandDistribution);
        surfaceTransitionPriorDistribution = surfaceTransitionPriorDistribution == null ? Map.of() : Map.copyOf(surfaceTransitionPriorDistribution);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}