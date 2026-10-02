package io.contexa.demo.observation.engine.dto;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record EngineObservation(
        UUID id,
        UUID requestId,
        String kind,
        Instant observedAt,
        Map<String, Object> payload) {

    public EngineObservation {
        payload = Map.copyOf(payload);
    }
}
