package io.contexa.demo.comparison.attestation.dto;

import io.contexa.demo.comparison.preparation.dto.PreparationBlocker;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AttestationPair(
        UUID preparationId,
        Instant checkedAt,
        List<ArmAttestation> attestations,
        List<PreparationBlocker> blockers,
        boolean initialConditionsMatch,
        String scope
) {
}
