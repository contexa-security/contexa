package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Portfolio-level strategy learning output.
 */
public record DetectionStrategyLearningPortfolio(
        long totalObservationCount,
        long classifiedObservationCount,
        long unclassifiedObservationCount,
        List<DetectionStrategyLearningFamilyResult> families,
        LocalDateTime generatedAt) {

    public DetectionStrategyLearningPortfolio {
        families = families == null ? List.of() : List.copyOf(families);
        generatedAt = generatedAt == null ? LocalDateTime.now() : generatedAt;
    }

    public static DetectionStrategyLearningPortfolio empty() {
        return new DetectionStrategyLearningPortfolio(0, 0, 0, List.of(), LocalDateTime.now());
    }
}
