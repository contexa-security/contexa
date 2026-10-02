package io.contexa.demo.experience.report.dto;

import java.time.Instant;
import java.util.UUID;

public record ReportSummary(UUID id, UUID runId, Instant createdAt, String contentSha256) {
}
