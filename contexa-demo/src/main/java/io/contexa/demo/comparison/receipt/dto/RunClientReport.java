package io.contexa.demo.comparison.receipt.dto;

import java.time.Instant;
import java.util.UUID;

public record RunClientReport(
        UUID runId,
        Instant receivedAt,
        String sha256,
        String source,
        RunClientReportInput observation
) {
}
