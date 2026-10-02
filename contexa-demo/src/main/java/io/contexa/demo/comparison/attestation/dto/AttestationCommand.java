package io.contexa.demo.comparison.attestation.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AttestationCommand(@NotNull UUID commandId, @NotNull UUID preparationId) {
}
