package io.contexa.demo.work.customer.dto;

import java.time.Instant;
import java.util.UUID;

public record CustomerReadResult(
        UUID requestId,
        CustomerDetail detail,
        String contentSha256,
        int contentBytes,
        Instant completedAt) {
}
