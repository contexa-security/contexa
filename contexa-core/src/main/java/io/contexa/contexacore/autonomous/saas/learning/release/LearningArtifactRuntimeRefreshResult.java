package io.contexa.contexacore.autonomous.saas.learning.release;

import java.util.List;

public record LearningArtifactRuntimeRefreshResult(
        String artifactType,
        boolean runtimeManaged,
        boolean invalidated,
        boolean refreshed,
        List<String> policyFacts) {

    public LearningArtifactRuntimeRefreshResult {
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}