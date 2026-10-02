package io.contexa.demo.identity.controller;

import io.contexa.demo.identity.dto.CsrfView;
import io.contexa.demo.identity.dto.IdentityView;
import io.contexa.demo.identity.service.IdentityQueryService;
import io.contexa.demo.shared.web.AbstractQueryController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IdentityController extends AbstractQueryController {

    private final IdentityQueryService service;

    public IdentityController(IdentityQueryService service) {
        this.service = service;
    }

    @GetMapping("/api/lab/identity")
    public ResponseEntity<IdentityView> identity(Authentication authentication, HttpServletRequest request) {
        return result(service.inspect(authentication, request));
    }

    @GetMapping("/api/auth/csrf")
    public ResponseEntity<CsrfView> csrf(CsrfToken token) {
        return result(new CsrfView(token.getToken(), token.getHeaderName(), token.getParameterName()));
    }
}
