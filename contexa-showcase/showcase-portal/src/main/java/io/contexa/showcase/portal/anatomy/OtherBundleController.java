package io.contexa.showcase.portal.anatomy;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * W7-13: visitor endpoint of the prompt modal's "what changed" (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.1): a
 * step's prompt and the same step of the same case under the other prompt bundle. The bundles are read from the seals
 * through control D, so it answers only where the portal has control D.
 */
@RestController
public class OtherBundleController {

    private final ObjectProvider<OtherBundles> bundles;

    public OtherBundleController(ObjectProvider<OtherBundles> bundles) {
        this.bundles = bundles;
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/other-bundle")
    public ResponseEntity<OtherBundleView> otherBundle(@PathVariable("runId") String runId,
                                                       @PathVariable("stepNo") int stepNo) {
        OtherBundles others = bundles.getIfAvailable();
        if (others == null || !AnatomyController.RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(others.view(runId, stepNo));
    }
}
