package io.contexa.demo.comparison.submission.dto;

import java.time.Instant;
import java.util.UUID;

public record RunSubmission(
        UUID id,
        UUID preparationId,
        UUID commandId,
        Instant startedAt,
        String inputSha256,
        String state,
        UUID runId,
        Integer httpStatus,
        Instant finishedAt,
        String reason
) {
}
