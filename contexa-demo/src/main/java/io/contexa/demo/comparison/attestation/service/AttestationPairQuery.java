package io.contexa.demo.comparison.attestation.service;

import io.contexa.demo.comparison.attestation.dto.AttestationPair;
import java.util.UUID;

public interface AttestationPairQuery {

    AttestationPair inspect(UUID visitorId, UUID preparationId, UUID baselineId, UUID contexaId);
}
