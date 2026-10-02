package io.contexa.demo.comparison.run.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record RunCommand(
        @NotNull UUID commandId,
        @NotNull UUID preparationId,
        @NotNull UUID baselineAttestationId,
        @NotNull UUID contexaAttestationId
) {
}
