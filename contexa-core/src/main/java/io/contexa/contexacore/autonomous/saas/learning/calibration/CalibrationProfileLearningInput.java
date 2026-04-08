package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.util.List;

/**
 * Input set for calibration profile learning.
 */
public record CalibrationProfileLearningInput(
        List<CalibrationLearningObservation> observations) {

    public CalibrationProfileLearningInput {
        observations = observations == null ? List.of() : List.copyOf(observations);
    }

    public static CalibrationProfileLearningInput empty() {
        return new CalibrationProfileLearningInput(List.of());
    }
}
