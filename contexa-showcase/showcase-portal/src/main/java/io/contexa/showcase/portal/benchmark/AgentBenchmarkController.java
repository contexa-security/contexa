package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * docs/agent Agent중심-화면 AS-11: the agent part of the benchmark, counted from stored runs by the agent task's own
 * scoring ({@link AgentBenchmarkService}); the visitor reads it, nothing is run. Cached for a minute like the benchmark.
 */
@RestController
public class AgentBenchmarkController {

    private static final Duration KEEP = Duration.ofMinutes(1);

    private final AgentBenchmarkService service;
    private final AgentTaskCatalog catalog;
    private final ObjectMapper json;
    private AgentBenchmarkService.View cached;
    private Instant cachedAt = Instant.MIN;

    public AgentBenchmarkController(AgentBenchmarkService service, AgentTaskCatalog catalog, ObjectMapper json) {
        this.service = service;
        this.catalog = catalog;
        this.json = json;
    }

    @GetMapping("/api/benchmark/agent")
    public synchronized AgentBenchmarkService.View agent() {
        Instant now = Instant.now();
        if (cached == null || Duration.between(cachedAt, now).compareTo(KEEP) >= 0) {
            List<AgentBenchmarkService.CatalogCase> cases = catalog.all().stream()
                    .map(task -> new AgentBenchmarkService.CatalogCase(task.key(),
                            RunOrchestrator.definitionSha256(json, task), task.oracle().classification()))
                    .toList();
            cached = service.view(cases);
            cachedAt = now;
        }
        return cached;
    }
}
