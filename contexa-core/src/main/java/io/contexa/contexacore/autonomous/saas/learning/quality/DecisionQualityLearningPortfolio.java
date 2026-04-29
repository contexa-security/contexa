package io.contexa.contexacore.autonomous.saas.learning.quality;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Portfolio result for decision-quality learning.
 */
public record DecisionQualityLearningPortfolio(
        long totalObservationCount,
        long classifiedObservationCount,
        long unclassifiedObservationCount,
        List<DecisionQualityScenarioResult> scenarios,
        LocalDateTime evaluatedAt) {

    public DecisionQualityLearningPortfolio {
        if (totalObservationCount < 0L) {
            throw new IllegalArgumentException("totalObservationCount must be >= 0");
        }
        if (classifiedObservationCount < 0L) {
            throw new IllegalArgumentException("classifiedObservationCount must be >= 0");
        }
        if (unclassifiedObservationCount < 0L) {
            throw new IllegalArgumentException("unclassifiedObservationCount must be >= 0");
        }
        scenarios = scenarios == null ? List.of() : List.copyOf(scenarios);
        evaluatedAt = evaluatedAt == null ? LocalDateTime.now() : evaluatedAt;
    }

    public static DecisionQualityLearningPortfolio empty() {
        return new DecisionQualityLearningPortfolio(0L, 0L, 0L, List.of(), LocalDateTime.now());
    }
}
