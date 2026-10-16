package io.contexa.contexaiam.admin.promptquality.governance;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

/**
 * W6-10 (P6-CHANGE-7): the operator API of the bundle rollback. The operator is the signed-in administrator; an
 * emergency stop is approved by another one.
 */
@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/releases")
@PreAuthorize("hasRole('ADMIN')")
public class PromptBundleRollbackApiController {

    private final PromptBundleRollbackService rollbackService;

    public PromptBundleRollbackApiController(PromptBundleRollbackService rollbackService) {
        this.rollbackService = Objects.requireNonNull(rollbackService, "rollbackService");
    }

    @PostMapping("/rollback")
    public ResponseEntity<PromptBundleRollbackService.Result> rollback(
            @RequestBody PromptBundleRollbackService.Request request, Authentication authentication) {
        PromptBundleRollbackService.Result result = rollbackService.rollback(request, authentication.getName());
        return PromptBundleRollbackService.REFUSED.equals(result.status())
                ? ResponseEntity.unprocessableEntity().body(result) : ResponseEntity.ok(result);
    }

    @PostMapping("/rollback/{executionKey}/approve")
    public ResponseEntity<PromptBundleRollbackService.Result> approve(@PathVariable("executionKey") String executionKey,
                                                                      Authentication authentication) {
        PromptBundleRollbackService.Result result = rollbackService.approve(executionKey, authentication.getName());
        return PromptBundleRollbackService.REFUSED.equals(result.status())
                ? ResponseEntity.unprocessableEntity().body(result) : ResponseEntity.ok(result);
    }
}
