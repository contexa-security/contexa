package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Internal runtime DTO consumed by the strategy runtime integration path.
 */
public record DetectionStrategyRuntimePack(
        String tenantId,
        boolean runtimeReady,
        List<RuntimeStrategyItem> strategies,
        LocalDateTime generatedAt) {

    public DetectionStrategyRuntimePack {
        strategies = strategies == null ? List.of() : List.copyOf(strategies);
    }

    public static DetectionStrategyRuntimePack empty() {
        return new DetectionStrategyRuntimePack(null, false, List.of(), null);
    }

    public record RuntimeStrategyItem(
            String strategyKey,
            String strategyVersion,
            String strategyFamily,
            List<String> supportedThreatGoals,
            List<String> requiredSignals,
            List<String> recommendedSignals,
            List<String> applicableContextClasses,
            long minimumEvidenceCount,
            String confidenceBand,
            LearningArtifactMetadata metadata,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public RuntimeStrategyItem {
            supportedThreatGoals = supportedThreatGoals == null ? List.of() : List.copyOf(supportedThreatGoals);
            requiredSignals = requiredSignals == null ? List.of() : List.copyOf(requiredSignals);
            recommendedSignals = recommendedSignals == null ? List.of() : List.copyOf(recommendedSignals);
            applicableContextClasses = applicableContextClasses == null ? List.of() : List.copyOf(applicableContextClasses);
            metadata = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}
