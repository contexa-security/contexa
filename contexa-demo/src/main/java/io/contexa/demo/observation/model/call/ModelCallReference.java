package io.contexa.demo.observation.model.call;

import io.contexa.contexacore.std.llm.observation.LlmObservationContext;

import java.util.UUID;

public record ModelCallReference(UUID observationId, LlmObservationContext source) {
}
