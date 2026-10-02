package io.contexa.demo.entry.dto;

import java.time.Instant;
import java.util.UUID;

public record EntrySession(
        String state,
        UUID visitorId,
        Instant expiresAt,
        boolean mailConfigured,
        PendingCode pending
) {

}
