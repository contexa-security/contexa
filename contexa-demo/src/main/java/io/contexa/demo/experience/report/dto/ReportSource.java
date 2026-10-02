package io.contexa.demo.experience.report.dto;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.UUID;

public record ReportSource(
        String arm,
        UUID requestId,
        String state,
        Instant capturedAt,
        String contentSha256,
        JsonNode evidence
) {
}
