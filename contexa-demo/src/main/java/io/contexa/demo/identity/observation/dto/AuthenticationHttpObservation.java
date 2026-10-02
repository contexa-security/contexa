package io.contexa.demo.identity.observation.dto;

import java.time.Instant;
import java.util.UUID;

public record AuthenticationHttpObservation(
        UUID requestId,
        String role,
        String method,
        String path,
        Instant occurredAt,
        int status,
        boolean authenticatedBefore,
        boolean authenticatedAfter,
        String username,
        String authenticationType,
        String sessionSha256
) {

}
