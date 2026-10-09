package io.contexa.showcase.portal.anatomy;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Visitor endpoints of the verdict anatomy (docs/showcase/데모-재설계.md 5.3): the anatomy of a step and, one click
 * deeper, the model call texts while they are kept. A run is addressed by its run ID, which the visitor's own screens
 * show; the records hold only the virtual company's data, and HTTP session identifiers are masked.
 */
@RestController
public class AnatomyController {

    static final Pattern RUN_ID = Pattern.compile("run-[0-9a-f]{12}");

    private final AnatomyStore store;

    public AnatomyController(AnatomyStore store) {
        this.store = store;
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/anatomy")
    public ResponseEntity<DecisionAnatomy> anatomy(@PathVariable("runId") String runId,
                                                   @PathVariable("stepNo") int stepNo) {
        if (!RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        return store.anatomy(runId, stepNo).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    /**
     * Where the engine input of a request differed from the same request of an earlier run (lab-3), compared on the
     * server; 404 when either run or step is unknown.
     */
    @GetMapping("/api/runs/{runId}/steps/{stepNo}/input-changes")
    public ResponseEntity<List<InputComparison.Change>> inputChanges(@PathVariable("runId") String runId,
                                                                     @PathVariable("stepNo") int stepNo,
                                                                     @RequestParam("against") String against) {
        if (!RUN_ID.matcher(runId).matches() || !RUN_ID.matcher(against).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        Optional<DecisionAnatomy> now = store.anatomy(runId, stepNo);
        Optional<DecisionAnatomy> before = store.anatomy(against, stepNo);
        if (now.isEmpty() || before.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(InputComparison.changes(before.get(), now.get()));
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/exchanges")
    public ResponseEntity<AnatomyStore.Exchanges> exchanges(@PathVariable("runId") String runId,
                                                            @PathVariable("stepNo") int stepNo) {
        if (!RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        return store.exchanges(runId, stepNo).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }
}
