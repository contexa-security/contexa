package io.contexa.contexacore.autonomous.saas.learning.quality;

import java.util.List;

/**
 * Aggregated bias result for a scenario class.
 */
public record DecisionBiasAggregationResult(
        long sampleSize,
        long operatorReviewedOutcomeCount,
        long falsePositiveCount,
        long falseNegativeCount,
        double falsePositiveRate,
        double falseNegativeRate,
        double challengeOverfireRate,
        double allowUnderfireRate,
        List<String> aggregationFacts) {

    public DecisionBiasAggregationResult {
        if (sampleSize < 0L) {
            throw new IllegalArgumentException("sampleSize must be >= 0");
        }
        if (operatorReviewedOutcomeCount < 0L) {
            throw new IllegalArgumentException("operatorReviewedOutcomeCount must be >= 0");
        }
        if (falsePositiveCount < 0L) {
            throw new IllegalArgumentException("falsePositiveCount must be >= 0");
        }
        if (falseNegativeCount < 0L) {
            throw new IllegalArgumentException("falseNegativeCount must be >= 0");
        }
        falsePositiveRate = requireFinite(falsePositiveRate, "falsePositiveRate");
        falseNegativeRate = requireFinite(falseNegativeRate, "falseNegativeRate");
        challengeOverfireRate = requireFinite(challengeOverfireRate, "challengeOverfireRate");
        allowUnderfireRate = requireFinite(allowUnderfireRate, "allowUnderfireRate");
        aggregationFacts = aggregationFacts == null ? List.of() : List.copyOf(aggregationFacts);
    }

    public static DecisionBiasAggregationResult empty() {
        return new DecisionBiasAggregationResult(0L, 0L, 0L, 0L, 0.0d, 0.0d, 0.0d, 0.0d, List.of());
    }

    private static double requireFinite(double value, String field) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(field + " must be finite");
        }
        return value;
    }
}
