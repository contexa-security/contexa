package io.contexa.showcase.portal.scoring;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

/**
 * The score of a run for the visitor's screens (docs/showcase/데모-재설계.md 5.0): every screen shows this result
 * instead of judging the answers itself. A run is addressed by its run ID, which the visitor's own screens show.
 */
@RestController
public class ScoreController {

    static final Pattern RUN_ID = Pattern.compile("run-[0-9a-f]{12}");

    private final RunScores scores;

    public ScoreController(RunScores scores) {
        this.scores = scores;
    }

    @GetMapping("/api/runs/{runId}/score")
    public ResponseEntity<RunScores.RunScore> score(@PathVariable("runId") String runId) {
        if (!RUN_ID.matcher(runId).matches()) {
            return ResponseEntity.notFound().build();
        }
        return scores.score(runId).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }
}
