package io.contexa.demo.experience.journey.dto;

import io.contexa.demo.comparison.run.dto.RunStep;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record JourneyRun(
        UUID id,
        String stepId,
        Instant createdAt,
        String state,
        String manifestSha256,
        List<RunStep> requests
) {
}
