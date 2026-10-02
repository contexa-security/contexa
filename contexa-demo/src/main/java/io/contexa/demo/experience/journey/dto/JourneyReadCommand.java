package io.contexa.demo.experience.journey.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;

public record JourneyReadCommand(
        @NotNull UUID commandId,
        @NotNull @Pattern(regexp = "S[0-9]{2}-[0-9]{1,2}") String stepId,
        @NotNull @Size(min = 2, max = 2) List<@NotNull @Valid JourneyReadObservation> observations
) {
}
