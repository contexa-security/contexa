package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;

import java.util.List;

/**
 * Raw input batch for detection strategy learning.
 */
public record DetectionStrategyLearningInput(
        List<DecisionFeedbackPayload> feedback,
        List<ThreatOutcomePayload> threatOutcomes,
        List<PromptContextAuditPayload> promptAudits,
        List<ModelPerformanceTelemetryPayload> modelTelemetry,
        List<StrategyCampaignObservation> campaignObservations) {

    public DetectionStrategyLearningInput {
        feedback = feedback == null ? List.of() : List.copyOf(feedback);
        threatOutcomes = threatOutcomes == null ? List.of() : List.copyOf(threatOutcomes);
        promptAudits = promptAudits == null ? List.of() : List.copyOf(promptAudits);
        modelTelemetry = modelTelemetry == null ? List.of() : List.copyOf(modelTelemetry);
        campaignObservations = campaignObservations == null ? List.of() : List.copyOf(campaignObservations);
    }

    public static DetectionStrategyLearningInput empty() {
        return new DetectionStrategyLearningInput(List.of(), List.of(), List.of(), List.of(), List.of());
    }
}
