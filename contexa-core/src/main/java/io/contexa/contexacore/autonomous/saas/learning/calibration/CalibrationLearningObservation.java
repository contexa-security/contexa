package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.util.List;
import java.util.Map;

/**
 * Correlated observation used by the calibration learning engine.
 */
public record CalibrationLearningObservation(
        String correlationId,
        String originalAction,
        String finalAction,
        String feedbackType,
        String outcomeType,
        String finalDisposition,
        String operatorReviewedOutcome,
        Double decisionConfidence,
        Integer aiAnalysisLevel,
        boolean promptAuditLinked,
        int deniedContextCount,
        boolean telemetryLinked,
        List<String> signalKeys,
        Map<String, Object> scenarioSignals,
        List<String> evidenceFacts) {

    public CalibrationLearningObservation {
        signalKeys = signalKeys == null ? List.of() : List.copyOf(signalKeys);
        scenarioSignals = scenarioSignals == null ? Map.of() : Map.copyOf(scenarioSignals);
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
