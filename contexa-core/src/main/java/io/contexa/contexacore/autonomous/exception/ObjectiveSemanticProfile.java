package io.contexa.contexacore.autonomous.exception;

import java.util.List;

public record ObjectiveSemanticProfile(
        String objectiveFamily,
        String resolvedOperation,
        String resolvedResourceFamily,
        boolean knownObjective,
        boolean readOnlyObjective,
        boolean containmentObjective,
        boolean learningObjective,
        boolean mutatingOperation,
        boolean exportOperation,
        List<String> semanticFacts) {

    public ObjectiveSemanticProfile {
        semanticFacts = semanticFacts == null ? List.of() : List.copyOf(semanticFacts);
    }
}
