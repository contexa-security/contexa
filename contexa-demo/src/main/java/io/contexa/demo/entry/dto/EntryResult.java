package io.contexa.demo.entry.dto;

import java.time.Instant;
import java.util.UUID;

public record EntryResult(
        int status,
        String state,
        UUID requestId,
        Instant expiresAt,
        Instant retryAt
) {

}
