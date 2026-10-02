package io.contexa.demo.readiness.dto;

import java.time.Instant;
import java.util.UUID;

public record StoredReadiness(
        UUID id,
        String role,
        Instant observedAt,
        Object snapshot,
        String sha256
) {

}
