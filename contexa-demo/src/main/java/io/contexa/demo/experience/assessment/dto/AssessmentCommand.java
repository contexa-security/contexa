package io.contexa.demo.experience.assessment.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public record AssessmentCommand(
        @NotNull UUID commandId,
        @NotNull AssessmentPosition position,
        UUID requestId,
        @NotBlank @Size(max = 1600) String comment
) {
}
