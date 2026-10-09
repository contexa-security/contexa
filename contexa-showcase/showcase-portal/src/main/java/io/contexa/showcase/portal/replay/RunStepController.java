package io.contexa.showcase.portal.replay;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

/**
 * The stored result of one step of a run, every approach side by side (docs/showcase/데모-재설계.md 5A.1 ③④, 5A.2 ③):
 * the same view the visitor's current run shows, read by run ID for an earlier run the lab compares with and for the
 * runs a benchmark cell lists. Stored records of the virtual company only; nothing is computed here.
 */
@RestController
public class RunStepController {

    static final Pattern RUN_ID = Pattern.compile("run-[0-9a-f]{12}");

    private final ReplayViews views;

    public RunStepController(ReplayViews views) {
        this.views = views;
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/result")
    public ResponseEntity<ReplayView.StepResult> result(@PathVariable("runId") String runId,
                                                        @PathVariable("stepNo") int stepNo) {
        if (!RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        return views.storedStep(runId, stepNo).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }
}
