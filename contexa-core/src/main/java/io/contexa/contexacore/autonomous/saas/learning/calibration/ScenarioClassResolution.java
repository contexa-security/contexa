package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.util.List;

/**
 * Scenario-class resolution result for a correlated observation.
 */
public record ScenarioClassResolution(
        String scenarioClass,
        List<String> resolutionFacts) {

    public ScenarioClassResolution {
        scenarioClass = scenarioClass == null ? null : scenarioClass.trim();
        resolutionFacts = resolutionFacts == null ? List.of() : List.copyOf(resolutionFacts);
    }

    public boolean isResolved() {
        return scenarioClass != null && !scenarioClass.isBlank();
    }

    public static ScenarioClassResolution unresolved() {
        return new ScenarioClassResolution(null, List.of());
    }
}
