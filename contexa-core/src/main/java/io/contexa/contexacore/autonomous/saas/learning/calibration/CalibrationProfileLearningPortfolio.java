package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Portfolio result for calibration learning.
 */
public record CalibrationProfileLearningPortfolio(
        long totalObservationCount,
        long classifiedObservationCount,
        long unclassifiedObservationCount,
        List<CalibrationProfileLearningScenarioResult> scenarios,
        LocalDateTime evaluatedAt) {

    public CalibrationProfileLearningPortfolio {
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

    public static CalibrationProfileLearningPortfolio empty() {
        return new CalibrationProfileLearningPortfolio(0L, 0L, 0L, List.of(), LocalDateTime.now());
    }
}
