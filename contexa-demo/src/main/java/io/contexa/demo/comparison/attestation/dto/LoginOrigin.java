package io.contexa.demo.comparison.attestation.dto;

import java.time.Instant;
import java.util.UUID;

public record LoginOrigin(UUID observationId, UUID requestId, Instant observedAt,
        String path, String authenticationType, int httpStatus) {
}
