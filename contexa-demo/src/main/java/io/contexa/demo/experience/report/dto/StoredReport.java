package io.contexa.demo.experience.report.dto;

import java.time.Instant;
import java.util.UUID;

public record StoredReport(
        UUID id,
        UUID runId,
        Instant createdAt,
        String contentSha256,
        String archiveState,
        ReportPayload payload
) {
}
