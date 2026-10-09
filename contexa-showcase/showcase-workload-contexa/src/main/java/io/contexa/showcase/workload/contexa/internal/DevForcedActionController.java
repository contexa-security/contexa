package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.showcase.workload.contexa.principal.OrphanPrincipalSweeper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Development-only forced engine decision, to check the challenge flow and the release of a block on a running stack
 * while the model makes no such decision by itself (docs/showcase/P3-설계.md, ADR-33). It exists only with
 * {@code showcase.dev.forced-actions=true}, accepts run principals only and CHALLENGE or BLOCK only, and the portal
 * neither records replays while it exists nor publishes a run that used it: visitors only ever see decisions the engine
 * made itself.
 *
 * <p>A forced BLOCK goes the way of the engine's own block (SecurityDecisionEnforcementHandler): the action, the blocked
 * flag, and the block record that the release request and the administrator's approval work on. No response is in
 * flight when a decision is forced before a step, so nothing waits for in-flight blocking.</p>
 */
@RestController
@ConditionalOnProperty(name = "showcase.dev.forced-actions", havingValue = "true")
public class DevForcedActionController {

    static final Set<ZeroTrustAction> FORCEABLE = Set.of(ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK);
    static final String REASONING = "Development-only forced decision (showcase.dev.forced-actions)";

    private final ZeroTrustActionRepository actions;
    private final ObjectProvider<IBlockedUserRecorder> blockedUsers;

    public DevForcedActionController(ZeroTrustActionRepository actions,
                                     ObjectProvider<IBlockedUserRecorder> blockedUsers) {
        this.actions = actions;
        this.blockedUsers = blockedUsers;
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
        actions.saveAction(username, forced, Map.of("reasoning", REASONING));
        if (forced == ZeroTrustAction.BLOCK) {
            IBlockedUserRecorder recorder = blockedUsers.getIfAvailable();
            if (recorder == null) {
                throw new IllegalStateException("No block recorder: a forced block could not be released");
            }
            actions.setBlockedFlag(username);
            recorder.recordBlock("dev-forced-" + UUID.randomUUID(), username, username, forced.name(), REASONING,
                    null, null);
        }
        return Map.of("username", username, "action", forced.name());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> refused(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
