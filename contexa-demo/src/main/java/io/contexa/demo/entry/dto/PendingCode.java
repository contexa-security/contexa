package io.contexa.demo.entry.dto;

import java.time.Instant;
import java.util.UUID;

public record PendingCode(
        UUID requestId,
        String state,
        Instant expiresAt,
        Instant retryAt
) {

}
