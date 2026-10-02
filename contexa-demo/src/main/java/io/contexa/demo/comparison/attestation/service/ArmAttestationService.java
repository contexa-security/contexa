package io.contexa.demo.comparison.attestation.service;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.dto.AttestationCommand;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import java.util.UUID;

public interface ArmAttestationService {

    ArmAttestation capture(UUID visitorId, AttestationCommand command, Authentication authentication,
            HttpServletRequest request);
}
