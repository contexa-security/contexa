package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Visitor API of what each decision does to the user's next requests (E1-7 and the follow-up map F of
 * docs/showcase/화면설계서-v2-구현계획.md): the HTTP status of a refused request and how long the decision stays in
 * force, as control D reads them from the engine's ZeroTrustAction. The values change only with the engine, so they are
 * reused for ten minutes.
 */
@RestController
@ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
public class EngineActionsController {

    static final Duration CACHE = Duration.ofMinutes(10);

    private final WorkloadAdmin admin;
    private final Clock clock = Clock.systemUTC();
    private JsonNode cached;
    private Instant cachedAt;

    public EngineActionsController(WorkloadAdmin admin) {
        this.admin = admin;
    }

    @GetMapping("/api/engine/actions")
    public synchronized ResponseEntity<JsonNode> actions() {
        Instant now = clock.instant();
        if (cached == null || !now.isBefore(cachedAt.plus(CACHE))) {
            try {
                JsonNode actions = admin.engine().path("actions");
                if (!actions.isObject()) {
                    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
                }
                cached = actions;
                cachedAt = now;
            } catch (IOException e) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
            }
        }
        return ResponseEntity.ok(cached);
    }
}
