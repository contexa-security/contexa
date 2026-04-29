package io.contexa.contexacore.autonomous.saas.learning.quality;

import java.util.List;

/**
 * Input set for decision-quality profile learning.
 */
public record DecisionQualityLearningInput(
        List<DecisionQualityObservation> observations) {

    public DecisionQualityLearningInput {
        observations = observations == null ? List.of() : List.copyOf(observations);
    }

    public static DecisionQualityLearningInput empty() {
        return new DecisionQualityLearningInput(List.of());
    }
}
