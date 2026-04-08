package io.contexa.contexacore.autonomous.saas.learning.prompt;

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;

import java.util.List;

/**
 * Raw experiment input joined only from presentation-safe learning feeds.
 */
public record PromptPresentationExperimentInput(
        List<PromptContextAuditPayload> promptAudits,
        List<DecisionFeedbackPayload> decisionFeedbacks,
        List<ThreatOutcomePayload> threatOutcomes,
        List<ModelPerformanceTelemetryPayload> performanceTelemetry) {

    public PromptPresentationExperimentInput {
        promptAudits = promptAudits == null ? List.of() : List.copyOf(promptAudits);
        decisionFeedbacks = decisionFeedbacks == null ? List.of() : List.copyOf(decisionFeedbacks);
        threatOutcomes = threatOutcomes == null ? List.of() : List.copyOf(threatOutcomes);
        performanceTelemetry = performanceTelemetry == null ? List.of() : List.copyOf(performanceTelemetry);
    }

    public static PromptPresentationExperimentInput empty() {
        return new PromptPresentationExperimentInput(List.of(), List.of(), List.of(), List.of());
    }
}