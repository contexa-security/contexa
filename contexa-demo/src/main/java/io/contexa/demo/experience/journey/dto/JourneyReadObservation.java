package io.contexa.demo.experience.journey.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.time.Instant;

public record JourneyReadObservation(
        @NotNull @Pattern(regexp = "baseline|contexa") String arm,
        @NotNull @Pattern(regexp = "/api/work/(projects|approvals)") String path,
        @Min(100) @Max(599) Integer httpStatus,
        @Pattern(regexp = "[a-f0-9]{64}") String contentSha256,
        @NotNull Instant observedAt
) {
}
