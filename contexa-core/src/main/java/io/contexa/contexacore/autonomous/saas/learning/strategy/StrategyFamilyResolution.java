package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.util.List;

/**
 * Family resolution result for a correlated observation.
 */
public record StrategyFamilyResolution(
        String strategyFamily,
        List<String> resolutionFacts) {

    public StrategyFamilyResolution {
        strategyFamily = strategyFamily == null ? null : strategyFamily.trim();
        resolutionFacts = resolutionFacts == null ? List.of() : List.copyOf(resolutionFacts);
    }

    public boolean isResolved() {
        return strategyFamily != null && !strategyFamily.isBlank();
    }

    public static StrategyFamilyResolution unresolved() {
        return new StrategyFamilyResolution(null, List.of());
    }
}
