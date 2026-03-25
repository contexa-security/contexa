package io.contexa.contexacore.autonomous.context;

import java.util.List;

public record ObjectiveDriftEvaluation(
        Boolean objectiveDrift,
        String comparisonSource,
        String currentActionFamily,
        String currentResourceFamily,
        List<String> allowedActionFamilies,
        List<String> allowedResourceFamilies,
        List<String> rawResourceConstraints,
        List<String> facts) {

    public ObjectiveDriftEvaluation {
        allowedActionFamilies = allowedActionFamilies == null ? List.of() : List.copyOf(allowedActionFamilies);
        allowedResourceFamilies = allowedResourceFamilies == null ? List.of() : List.copyOf(allowedResourceFamilies);
        rawResourceConstraints = rawResourceConstraints == null ? List.of() : List.copyOf(rawResourceConstraints);
        facts = facts == null ? List.of() : List.copyOf(facts);
    }
}
