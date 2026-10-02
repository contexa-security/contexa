package io.contexa.demo.entry.controller;

import io.contexa.demo.entry.dto.EntryLocation;
import io.contexa.demo.entry.dto.EntrySession;
import io.contexa.demo.entry.service.EntrySessionService;
import io.contexa.demo.entry.token.VisitorTokens;
import io.contexa.demo.shared.web.AbstractQueryController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lab/entry")
public class EntryQueryController extends AbstractQueryController {

    private final EntrySessionService sessions;
    private final VisitorTokens tokens;

    public EntryQueryController(EntrySessionService sessions, VisitorTokens tokens) {
        this.sessions = sessions;
        this.tokens = tokens;
    }

    @GetMapping("/session")
    public ResponseEntity<EntrySession> session(HttpServletRequest request) {
        return result(sessions.inspect(tokens.hash(tokens.read(request))));
    }

    @GetMapping("/location")
    public ResponseEntity<EntryLocation> location() {
        return result(sessions.location());
    }
}
