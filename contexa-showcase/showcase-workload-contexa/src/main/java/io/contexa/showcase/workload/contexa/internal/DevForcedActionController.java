package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.showcase.workload.contexa.principal.OrphanPrincipalSweeper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

/**
 * Development-only forced engine decision, to check the challenge flow on a running stack while the model makes no
 * such decision by itself (docs/showcase/P3-설계.md). It exists only with {@code showcase.dev.forced-actions=true},
 * accepts run principals only and CHALLENGE only, and the portal neither records replays while it exists nor publishes
 * a run that used it: visitors only ever see decisions the engine made itself.
 */
@RestController
@ConditionalOnProperty(name = "showcase.dev.forced-actions", havingValue = "true")
public class DevForcedActionController {

    static final Set<ZeroTrustAction> FORCEABLE = Set.of(ZeroTrustAction.CHALLENGE);

    private final ZeroTrustActionRepository actions;

    public DevForcedActionController(ZeroTrustActionRepository actions) {
        this.actions = actions;
    }

    @PostMapping("/internal/dev/actions/{username}")
    public Map<String, String> force(@PathVariable("username") String username,
                                     @RequestParam("action") String action) {
        if (!username.matches(OrphanPrincipalSweeper.PRINCIPAL_PATTERN)) {
            throw new IllegalArgumentException("Only run principals take a forced decision");
        }
        ZeroTrustAction forced = ZeroTrustAction.valueOf(action);
        if (!FORCEABLE.contains(forced)) {
            throw new IllegalArgumentException("Only " + FORCEABLE + " can be forced");
        }
        actions.saveAction(username, forced, Map.of());
        return Map.of("username", username, "action", forced.name());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> refused(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
