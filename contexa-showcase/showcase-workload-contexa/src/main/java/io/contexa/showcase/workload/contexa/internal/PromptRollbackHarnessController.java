package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * W8-3 (P8 rollback rehearsal on control D): the measurement harness's bundle rollback and its approval (internal
 * API, guarded like every {@code /internal/**} path), through the same OSS rollback service as the OSS operator API
 * (PromptBundleRollbackApiController). The rollback is asked by the harness and approved by a second harness actor,
 * because the service refuses an approval by the actor who asked; the rehearsal's record says so.
 */
@RestController
public class PromptRollbackHarnessController {

    static final String ACTOR = PromptReleaseHarnessController.ACTOR;
    static final String APPROVER = "showcase-ops-approver";

    private final ObjectProvider<PromptBundleRollbackService> rollbacks;

    public PromptRollbackHarnessController(ObjectProvider<PromptBundleRollbackService> rollbacks) {
        this.rollbacks = rollbacks;
    }

    @PostMapping("/internal/prompt-releases/rollback")
    public ResponseEntity<PromptBundleRollbackService.Result> rollback(
            @RequestBody PromptBundleRollbackService.Request request) {
        PromptBundleRollbackService service = rollbacks.getIfAvailable();
        if (service == null) {
            return ResponseEntity.notFound().build();
        }
        PromptBundleRollbackService.Result result = service.rollback(request, ACTOR);
        return answer(result);
    }

    @PostMapping("/internal/prompt-releases/rollback/{executionKey}/approve")
    public ResponseEntity<PromptBundleRollbackService.Result> approve(
            @PathVariable("executionKey") String executionKey) {
        PromptBundleRollbackService service = rollbacks.getIfAvailable();
        if (service == null) {
            return ResponseEntity.notFound().build();
        }
        return answer(service.approve(executionKey, APPROVER));
    }

    private static ResponseEntity<PromptBundleRollbackService.Result> answer(PromptBundleRollbackService.Result result) {
        return PromptBundleRollbackService.REFUSED.equals(result.status())
                ? ResponseEntity.unprocessableEntity().body(result) : ResponseEntity.ok(result);
    }
}
