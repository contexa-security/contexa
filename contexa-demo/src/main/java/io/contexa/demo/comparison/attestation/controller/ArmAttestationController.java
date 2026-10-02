package io.contexa.demo.comparison.attestation.controller;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.dto.AttestationCommand;
import io.contexa.demo.comparison.attestation.service.ArmAttestationService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile({"baseline", "contexa"})
public class ArmAttestationController extends AbstractVisitorController {

    private final ArmAttestationService service;

    public ArmAttestationController(ArmAttestationService service) {
        this.service = service;
    }

    @PostMapping("/api/lab/comparisons/attestations")
    public ResponseEntity<ArmAttestation> capture(@Valid @RequestBody AttestationCommand command,
            Authentication authentication, HttpServletRequest request) {
        return result(service.capture(visitorId(request), command, authentication, request));
    }
}
