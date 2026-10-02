package io.contexa.demo.work.document.dto;

import java.time.Instant;
import java.util.UUID;

public record DocumentReadResult(
        UUID requestId,
        DocumentBody document,
        String contentSha256,
        int contentBytes,
        Instant completedAt) {
}
