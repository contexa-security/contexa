package io.contexa.demo.observation.model.dto;

import io.contexa.contexacore.std.llm.observation.LlmObservationContext;

import java.time.Instant;
import java.util.UUID;

public record ModelBoundaryObservation(
        UUID id,
        String inputSha256,
        String outputSanitized,
        boolean outputTruncated,
        String responseModel,
        Integer inputTokens,
        Integer outputTokens,
        Instant startedAt,
        Instant completedAt,
        String failureType,
        LlmObservationContext source) {
}
