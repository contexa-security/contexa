package io.contexa.demo.observation.receipt.dto;

import java.time.Instant;
import java.util.UUID;

public record ClientReceiptView(
        UUID id,
        UUID requestId,
        String arm,
        ReceiptState state,
        long receivedBytes,
        String contentSha256,
        Instant clientStartedAt,
        Instant clientEndedAt,
        Instant reportedAt,
        String source,
        Boolean matchesPreparedFile) {
}
