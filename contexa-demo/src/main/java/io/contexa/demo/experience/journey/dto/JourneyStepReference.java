package io.contexa.demo.experience.journey.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.UUID;

public record JourneyStepReference(
        @NotNull UUID journeyId,
        @NotNull @Pattern(regexp = "S[0-9]{2}-[0-9]{1,2}") String stepId
) {
}
