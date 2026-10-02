package io.contexa.demo.experience.journey.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.UUID;

public record JourneyCommand(
        @NotNull UUID commandId,
        @NotNull UUID scenarioId,
        @NotBlank @Pattern(regexp = "[a-zA-Z0-9._@-]{1,100}") String account
) {
}
