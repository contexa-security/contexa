package io.contexa.demo.comparison.attestation.repository;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import java.util.UUID;

public interface ArmAttestationRepository {

    ArmAttestation findCommand(UUID visitorId, UUID commandId);

    ArmAttestation save(ArmAttestation candidate);
}
