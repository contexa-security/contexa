package io.contexa.demo.identity.controller;

import io.contexa.demo.identity.dto.AccessObservation;
import io.contexa.demo.shared.web.AbstractQueryController;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lab/access")
public class AccessObservationController extends AbstractQueryController {

    @GetMapping
    public ResponseEntity<AccessObservation> authenticated(Authentication auth) {
        return result(new AccessObservation(auth.getName(), "AUTHENTICATED", "SHARED_STATIC_POLICY"));
    }

    @GetMapping("/admin")
    public ResponseEntity<AccessObservation> admin(Authentication auth) {
        return result(new AccessObservation(auth.getName(), "ROLE_ADMIN", "SHARED_STATIC_POLICY"));
    }
}
