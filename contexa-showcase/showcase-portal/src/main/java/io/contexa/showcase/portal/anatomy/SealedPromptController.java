package io.contexa.showcase.portal.anatomy;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * W7-13: visitor endpoints of a step's sealed prompt (docs/showcase/화면설계-프롬프트신뢰-보강안.md 5): the facts the
 * model received by block with their sources, and the quality ribbon with the bundle, the seal and the inspection.
 * Control D gives the sealed prompt, so both answer only where the portal has control D; a step without a seal is
 * answered with the reason.
 */
@RestController
public class SealedPromptController {

    private final ObjectProvider<SealedPrompts> prompts;

    public SealedPromptController(ObjectProvider<SealedPrompts> prompts) {
        this.prompts = prompts;
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/facts")
    public ResponseEntity<SealedPromptViews.FactsView> facts(@PathVariable("runId") String runId,
                                                             @PathVariable("stepNo") int stepNo) {
        SealedPrompts sealed = prompts.getIfAvailable();
        if (sealed == null || !AnatomyController.RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        SealedPrompts.Read read = sealed.step(runId, stepNo);
        return ResponseEntity.ok(SealedPromptViews.facts(runId, stepNo, read.reason(), read.facts()));
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/quality")
    public ResponseEntity<SealedPromptViews.QualityView> quality(@PathVariable("runId") String runId,
                                                                 @PathVariable("stepNo") int stepNo) {
        SealedPrompts sealed = prompts.getIfAvailable();
        if (sealed == null || !AnatomyController.RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        SealedPrompts.Read read = sealed.step(runId, stepNo);
        return ResponseEntity.ok(SealedPromptViews.quality(read.reason(), read.facts()));
    }
}
