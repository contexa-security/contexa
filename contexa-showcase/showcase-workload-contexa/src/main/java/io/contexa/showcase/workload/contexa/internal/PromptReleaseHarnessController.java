package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * W6-9 (P6): the release transition of the measurement harness on control D (internal API, guarded like every
 * {@code /internal/**} path). It goes through the same OSS release gate and runtime cache invalidation as the OSS
 * operator API (PromptReleaseTransitionApiController), for the security decision prompt of the platform scope, so the
 * portal's operator port can put a bundle in the shadow release without the administrator's password.
 */
@RestController
public class PromptReleaseHarnessController {

    static final String ACTOR = "showcase-ops-harness";
    static final String SOURCE = "SHOWCASE_OPS_HARNESS";
    static final String PROMPT_KEY = "cortex.security-decision";

    private final ObjectProvider<PromptGovernanceReleaseGateService> gate;
    private final ObjectProvider<PromptGovernanceRuntimeCacheInvalidationService> invalidation;

    public PromptReleaseHarnessController(
            ObjectProvider<PromptGovernanceReleaseGateService> gate,
            ObjectProvider<PromptGovernanceRuntimeCacheInvalidationService> invalidation) {
        this.gate = gate;
        this.invalidation = invalidation;
    }

    /** The bundle version, the state it should take (a name of any vocabulary, N-GOV-4) and why. */
    public record TransitionRequest(String promptVersion, String targetReleaseStatus, String rationale) {
    }

    @PostMapping("/internal/prompt-releases/transition")
    public ResponseEntity<PromptGovernanceReleaseGateService.ReleaseTransitionReceipt> transition(
            @RequestBody TransitionRequest request) {
        PromptGovernanceReleaseGateService releases = gate.getIfAvailable();
        if (releases == null) {
            return ResponseEntity.notFound().build();
        }
        // N-GOV-4: the requested name reads through the one table of PromptBundleState, the canonical name first.
        Optional<PromptBundleState> target = PromptBundleState.fromStoredValue(request.targetReleaseStatus());
        if (request.promptVersion() == null || request.promptVersion().isBlank()
                || target.isEmpty() || request.rationale() == null
                || request.rationale().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        String scope = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = releases.transitionPromptRelease(scope,
                PROMPT_KEY, request.promptVersion(), target.get(), ACTOR, request.rationale(), SOURCE);
        if (!receipt.applied()) {
            return ResponseEntity.unprocessableEntity().body(receipt);
        }
        PromptGovernanceRuntimeCacheInvalidationService caches = invalidation.getIfAvailable();
        if (caches != null) {
            caches.publish(scope, PROMPT_KEY, request.promptVersion(),
                    "release transition to " + target.get().name(), ACTOR);
        }
        return ResponseEntity.ok(receipt);
    }
}
