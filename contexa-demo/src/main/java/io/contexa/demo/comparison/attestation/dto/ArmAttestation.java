package io.contexa.demo.comparison.attestation.dto;

import java.time.Instant;
import java.util.UUID;

public record ArmAttestation(
        UUID id,
        UUID visitorId,
        UUID workspaceId,
        UUID preparationId,
        UUID commandId,
        String arm,
        Instant capturedAt,
        String snapshotSha256,
        AttestationSnapshot snapshot
) {
}
