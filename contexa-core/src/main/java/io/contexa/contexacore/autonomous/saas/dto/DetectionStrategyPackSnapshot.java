package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record DetectionStrategyPackSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean runtimeReady,
        String promotionState,
        long promotedStrategyCount,
        long candidateStrategyCount,
        long collectingStrategyCount,
        List<StrategyItem> strategies,
        LocalDateTime generatedAt) {

    public DetectionStrategyPackSnapshot {
        strategies = strategies == null ? List.of() : List.copyOf(strategies);
    }

    public static DetectionStrategyPackSnapshot empty() {
        return new DetectionStrategyPackSnapshot(null, false, false, false, "DISABLED", 0L, 0L, 0L, List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record StrategyItem(
            String strategyKey,
            String strategyVersion,
            String strategyFamily,
            List<String> supportedThreatGoals,
            List<String> requiredSignals,
            List<String> recommendedSignals,
            List<String> applicableContextClasses,
            long minimumEvidenceCount,
            String confidenceBand,
            double localLiftRate,
            double fpDelta,
            double fnDelta,
            long sampleSize,
            double outcomeCoverageRate,
            double hardNegativeCoverage,
            boolean runtimeEligible,
            String promotionState,
            List<String> guardrails,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public StrategyItem {
            supportedThreatGoals = supportedThreatGoals == null ? List.of() : List.copyOf(supportedThreatGoals);
            requiredSignals = requiredSignals == null ? List.of() : List.copyOf(requiredSignals);
            recommendedSignals = recommendedSignals == null ? List.of() : List.copyOf(recommendedSignals);
            applicableContextClasses = applicableContextClasses == null ? List.of() : List.copyOf(applicableContextClasses);
            guardrails = guardrails == null ? List.of() : List.copyOf(guardrails);
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}
