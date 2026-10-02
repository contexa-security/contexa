package io.contexa.demo.comparison.attestation.controller;

import io.contexa.demo.comparison.attestation.dto.AttestationPair;
import io.contexa.demo.comparison.attestation.service.AttestationPairQuery;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;

@RestController
@Profile("portal")
public class AttestationPairController extends AbstractVisitorController {

    private final AttestationPairQuery query;

    public AttestationPairController(AttestationPairQuery query) {
        this.query = query;
    }

    @GetMapping("/api/lab/comparisons/preparations/{id}/sessions")
    public ResponseEntity<AttestationPair> inspect(@PathVariable UUID id,
            @RequestParam(required = false) UUID baseline, @RequestParam(required = false) UUID contexa,
            HttpServletRequest request) {
        return result(query.inspect(visitorId(request), id, baseline, contexa));
    }
}
