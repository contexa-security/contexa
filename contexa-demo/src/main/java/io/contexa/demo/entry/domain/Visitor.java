package io.contexa.demo.entry.domain;

import java.time.Instant;
import java.util.UUID;

public record Visitor(
        UUID id,
        String email,
        Instant verifiedAt,
        Instant expiresAt
) {

    public boolean verified() {
        return verifiedAt != null;
    }
}
