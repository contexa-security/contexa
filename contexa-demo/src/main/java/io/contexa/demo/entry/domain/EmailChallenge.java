package io.contexa.demo.entry.domain;

import java.time.Instant;
import java.util.UUID;

public record EmailChallenge(
        UUID id,
        UUID visitorId,
        String email,
        String codeHash,
        String state,
        Instant createdAt,
        Instant expiresAt,
        int attempts
) {

}
