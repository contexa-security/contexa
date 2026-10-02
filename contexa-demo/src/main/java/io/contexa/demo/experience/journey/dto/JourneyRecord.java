package io.contexa.demo.experience.journey.dto;

import java.time.Instant;
import java.util.UUID;

public record JourneyRecord(
        UUID id,
        Instant createdAt,
        String inputSha256,
        String contentSha256,
        JourneySnapshot snapshot
) {
}
