package io.contexa.demo.experience.journey.dto;

import java.time.Instant;
import java.util.UUID;

public record JourneyReadRecord(
        UUID id,
        UUID journeyId,
        Instant createdAt,
        String inputSha256,
        JourneyReadCommand reported
) {
}
