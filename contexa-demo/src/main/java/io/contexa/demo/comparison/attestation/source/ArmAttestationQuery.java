package io.contexa.demo.comparison.attestation.source;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import java.util.UUID;

public interface ArmAttestationQuery {

    String arm();

    ArmAttestation find(UUID visitorId, UUID preparationId, UUID id);
}
