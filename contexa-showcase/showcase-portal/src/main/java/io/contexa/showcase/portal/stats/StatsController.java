package io.contexa.showcase.portal.stats;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Visitor API of the execution statistics (deck p.17); counted from the stored runs, cached for a minute. */
@RestController
public class StatsController {

    private final ExecutionStats stats;

    public StatsController(ExecutionStats stats) {
        this.stats = stats;
    }

    @GetMapping("/api/stats")
    public StatsView stats() {
        return stats.view();
    }
}
