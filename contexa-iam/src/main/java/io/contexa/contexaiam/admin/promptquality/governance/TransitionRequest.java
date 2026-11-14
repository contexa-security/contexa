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
 * What the operator asks: a bundle of a scope and the state it should take, named in the canonical vocabulary
 * (decision 1) or in an older one the one table of {@link PromptBundleState} reads (N-GOV-4).
 */
public record TransitionRequest(String registryScope, String promptKey, String promptVersion,
                                String targetReleaseStatus, String rationale) {
}
