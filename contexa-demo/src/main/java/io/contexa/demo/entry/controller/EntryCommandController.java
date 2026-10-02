package io.contexa.demo.entry.controller;

import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.entry.dto.CodeRequest;
import io.contexa.demo.entry.dto.CodeVerification;
import io.contexa.demo.entry.dto.EntryResult;
import io.contexa.demo.entry.service.EntryService;
import io.contexa.demo.entry.service.EntrySessionService;
import io.contexa.demo.entry.token.VisitorTokens;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/entry")
public class EntryCommandController {

    private final EntryService service;
    private final EntrySessionService visitors;
    private final VisitorTokens tokens;
    private final EntryProperties properties;

    public EntryCommandController(EntryService service, EntrySessionService visitors, VisitorTokens tokens,
            EntryProperties properties) {
        this.service = service;
        this.visitors = visitors;
        this.tokens = tokens;
        this.properties = properties;
    }

    @PostMapping("/requests")
    public ResponseEntity<EntryResult> request(@Valid @RequestBody CodeRequest input,
            HttpServletRequest request, HttpServletResponse response) {
        String token = tokens.read(request);
        boolean fresh = "NOT_VERIFIED".equals(visitors.inspect(tokens.hash(token)).state());
        if (fresh) {
            token = tokens.generate();
        }
        var result = service.request(tokens.hash(token), input.requestId(), input.email(), request.getRemoteAddr(),
                input.language());
        if (fresh) {
            tokens.set(response, token, properties.pendingLifetime());
        }
        return ResponseEntity.status(result.status()).cacheControl(CacheControl.noStore()).body(result);
    }

    @PostMapping("/verify")
    public ResponseEntity<EntryResult> verify(@Valid @RequestBody CodeVerification input,
            HttpServletRequest request, HttpServletResponse response) {
        String next = tokens.generate();
        var result =
                service.verify(tokens.hash(tokens.read(request)), input.requestId(), input.code(), tokens.hash(next));
        if ("VERIFIED".equals(result.state())) {
            tokens.set(response, next, properties.verifiedLifetime());
        }
        return ResponseEntity.status(result.status()).cacheControl(CacheControl.noStore()).body(result);
    }
}
