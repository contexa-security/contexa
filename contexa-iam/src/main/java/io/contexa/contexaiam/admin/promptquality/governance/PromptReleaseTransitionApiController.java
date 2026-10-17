package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;
import java.util.Optional;

/**
 * W6-8 (design 9.3-6): the OSS operator API of the registry transitions. Every transition goes through the release
 * gate; an applied one tells the runtime caches, so the bundle selector reads the new state.
 */
@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/releases")
@PreAuthorize("hasRole('ADMIN')")
public class PromptReleaseTransitionApiController {

    private final PromptGovernanceReleaseGateService gate;
    private final PromptGovernanceRuntimeCacheInvalidationService invalidation;

    public PromptReleaseTransitionApiController(PromptGovernanceReleaseGateService gate,
                                                PromptGovernanceRuntimeCacheInvalidationService invalidation) {
        this.gate = Objects.requireNonNull(gate, "gate");
        this.invalidation = Objects.requireNonNull(invalidation, "invalidation");
    }

    /**
     * What the operator asks: a bundle of a scope and the state it should take, named in the canonical vocabulary
     * (decision 1) or in an older one the one table of {@link PromptBundleState} reads (N-GOV-4).
     */
    public record TransitionRequest(String registryScope, String promptKey, String promptVersion,
                                    String targetReleaseStatus, String rationale) {
    }

    @PostMapping("/transition")
    public ResponseEntity<PromptGovernanceReleaseGateService.ReleaseTransitionReceipt> transition(
            @RequestBody TransitionRequest request, Authentication authentication) {
        // N-GOV-4: the requested name reads through the one table of PromptBundleState (decision 1), the canonical
        // name first and an older one as the state it means; a name of no vocabulary is a bad request.
        Optional<PromptBundleState> target = PromptBundleState.fromStoredValue(request.targetReleaseStatus());
        if (target.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = gate.transitionPromptRelease(
                request.registryScope(), request.promptKey(), request.promptVersion(), target.get(),
                authentication.getName(), request.rationale(), "OSS_OPERATOR_API");
        if (!receipt.applied()) {
            return ResponseEntity.unprocessableEntity().body(receipt);
        }
        invalidation.publish(request.registryScope(), request.promptKey(), request.promptVersion(),
                "release transition to " + target.get().name(), authentication.getName());
        return ResponseEntity.ok(receipt);
    }
}
