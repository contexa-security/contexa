package io.contexa.demo.observation.decision.dto;

import java.time.LocalDateTime;

public record NativeDecisionView(
        String observationId,
        String eventId,
        String requestId,
        String processingGeneration,
        String finalAction,
        String proposedAction,
        String decisionBoundaryMode,
        Boolean success,
        Boolean llmDecisionPresent,
        Boolean technicalFallback,
        String failureType,
        LocalDateTime decidedAt) {
}
