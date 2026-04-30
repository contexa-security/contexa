package io.contexa.contexacore.autonomous.saas.learning.quality;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;

import java.util.List;
import java.util.Objects;

/**
 * Assembly input that combines a scenario result with artifact metadata.
 */
public record DecisionQualityProfileCandidate(
        DecisionQualityScenarioResult scenarioResult,
        LearningArtifactMetadata metadata,
        List<String> policyFacts) {

    public DecisionQualityProfileCandidate {
        scenarioResult = Objects.requireNonNull(scenarioResult, "scenarioResult is required");
        metadata = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}
