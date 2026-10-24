package io.contexa.showcase.portal.ops;

import io.contexa.showcase.portal.orchestrator.ConsoleSessions;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * docs/agent RW-2 (A1-6): an operator's own browser session on control D's admin console, for checking the console's
 * screens in a real browser. Opening one creates a security administrator of control D and answers its sign-in;
 * the one-time code is read from the demo inbox; closing removes the administrator, as does its lifetime
 * ({@link ConsoleSessions#LIFETIME}). On the operator port only, like every ops route.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class ConsoleSessionOpsController implements DisposableBean {

    private static final String KEY = "[0-9a-f]{12}";

    private final ObjectProvider<WorkloadAdmin> admin;
    private final ObjectProvider<ControlEndpoints> endpoints;
    private ConsoleSessions sessions;

    public ConsoleSessionOpsController(ObjectProvider<WorkloadAdmin> admin,
                                       ObjectProvider<ControlEndpoints> endpoints) {
        this.admin = admin;
        this.endpoints = endpoints;
    }

    @PostMapping("/ops/console-sessions")
    public ResponseEntity<Map<String, Object>> open() throws IOException {
        ConsoleSessions open = sessions();
        ControlEndpoints controls = endpoints.getIfAvailable();
        if (open == null || controls == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        ConsoleSessions.Session session = open.open();
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("key", session.key());
        answer.put("username", session.username());
        answer.put("password", session.password());
        answer.put("email", session.email());
        answer.put("console", controls.of(Control.D).toString());
        answer.put("expiresAt", session.expiresAt().toString());
        return ResponseEntity.ok(answer);
    }

    @GetMapping("/ops/console-sessions/{key}/code")
    public ResponseEntity<Map<String, Object>> code(@PathVariable("key") String key) throws IOException {
        ConsoleSessions open = sessions();
        if (open == null || !key.matches(KEY)) {
            return ResponseEntity.notFound().build();
        }
        return open.code(key).<ResponseEntity<Map<String, Object>>>map(code -> ResponseEntity.ok(Map.of("code", code)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/ops/console-sessions/{key}")
    public ResponseEntity<Void> close(@PathVariable("key") String key) throws IOException {
        ConsoleSessions open = sessions();
        if (open == null || !key.matches(KEY) || !open.close(key)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.noContent().build();
    }

    @Override
    public void destroy() {
        if (sessions != null) {
            sessions.closeAll();
        }
    }

    private synchronized ConsoleSessions sessions() {
        if (sessions == null) {
            WorkloadAdmin workloadAdmin = admin.getIfAvailable();
            if (workloadAdmin == null) {
                return null;
            }
            sessions = new ConsoleSessions(workloadAdmin, Clock.systemUTC());
        }
        return sessions;
    }
}
