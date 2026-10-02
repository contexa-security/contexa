package io.contexa.demo.comparison.run.dto;

import java.time.Instant;
import java.util.UUID;

public record RunStep(
        UUID id,
        UUID runId,
        String arm,
        int ordinal,
        String state,
        UUID requestId,
        Instant startedAt,
        Instant respondedAt,
        Integer httpStatus,
        String failureType
) {
}
