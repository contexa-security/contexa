package io.contexa.contexacore.autonomous.saas.learning.calibration;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultDecisionBiasAggregatorTest {

    private final DefaultDecisionBiasAggregator aggregator = new DefaultDecisionBiasAggregator();

    @Test
    void calculatesChallengeOverfireBias() {
        DecisionBiasAggregationResult result = aggregator.aggregate("LOW_DIVERSITY_EXPORT_APPROACH", List.of(
                observation("CHALLENGE", "FALSE_POSITIVE", 0.91d),
                observation("CHALLENGE", "BENIGN", 0.88d),
                observation("ALLOW", "ALLOW", 0.73d)));

        assertThat(result.sampleSize()).isEqualTo(3L);
        assertThat(result.operatorReviewedOutcomeCount()).isEqualTo(3L);
        assertThat(result.falsePositiveCount()).isEqualTo(2L);
        assertThat(result.falseNegativeCount()).isZero();
        assertThat(result.challengeOverfireRate()).isEqualTo(1.0d);
        assertThat(result.allowUnderfireRate()).isZero();
        assertThat(result.recommendedConfidenceAdjustment()).isNegative();
        assertThat(result.recommendedActionBias()).isEqualTo("DECREASE_CHALLENGE");
    }

    @Test
    void calculatesAllowUnderfireBias() {
        DecisionBiasAggregationResult result = aggregator.aggregate("SESSION_PATH_SIMILARITY_BREAK", List.of(
                observation("ALLOW", "CONFIRMED_ATTACK", 0.92d),
                observation("ALLOW", "FALSE_NEGATIVE", 0.84d),
                observation("CHALLENGE", "ALLOW", 0.69d)));

        assertThat(result.falsePositiveCount()).isEqualTo(1L);
        assertThat(result.falseNegativeCount()).isEqualTo(2L);
        assertThat(result.challengeOverfireRate()).isEqualTo(1.0d);
        assertThat(result.allowUnderfireRate()).isEqualTo(1.0d);
        assertThat(result.recommendedConfidenceAdjustment()).isPositive();
        assertThat(result.recommendedActionBias()).isEqualTo("INCREASE_CHALLENGE");
        assertThat(result.aggregationFacts()).anyMatch(fact -> fact.contains("Reviewed outcome distribution"));
    }

    private CalibrationLearningObservation observation(String action, String reviewedOutcome, double confidence) {
        return new CalibrationLearningObservation(
                "corr",
                action,
                action,
                reviewedOutcome,
                reviewedOutcome,
                reviewedOutcome,
                reviewedOutcome,
                confidence,
                2,
                true,
                1,
                true,
                List.of("signal"),
                Map.of(),
                List.of("evidence"));
    }
}
