package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.util.List;
import java.util.Map;

/**
 * Correlated observation used by the detection strategy engine.
 */
public record StrategyLearningObservation(
        String correlationId,
        String feedbackType,
        String originalAction,
        String finalAction,
        String outcomeType,
        String finalDisposition,
        Integer aiAnalysisLevel,
        boolean promptAuditLinked,
        int deniedContextCount,
        boolean telemetryLinked,
        double layer1EscalationRate,
        double blockRate,
        double challengeRate,
        boolean campaignObserved,
        List<String> signalKeys,
        Map<String, Object> strategySignals,
        List<String> evidenceFacts) {

    public StrategyLearningObservation {
        signalKeys = signalKeys == null ? List.of() : List.copyOf(signalKeys);
        strategySignals = strategySignals == null ? Map.of() : Map.copyOf(strategySignals);
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
