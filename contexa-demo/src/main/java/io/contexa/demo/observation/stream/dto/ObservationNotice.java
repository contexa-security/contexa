package io.contexa.demo.observation.stream.dto;

import java.time.Instant;
import java.util.UUID;

public record ObservationNotice(
        long sequence,
        UUID observationId,
        UUID requestId,
        String kind,
        Instant observedAt,
        Instant collectedAt,
        String contentSha256) {
}
