package io.contexa.showcase.portal.menu;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.scenario.AgentPaths;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

/**
 * docs/agent Agent중심-화면 AC-4a: the agent menu's daily job. It runs each of the fifteen combinations with the real
 * engine, one after the other, and keeps the run that finished as the answer of its combination. Before each run it
 * asks what the job has spent so far; at the daily limit it stops and counts the rest as skipped. A run that does not
 * finish, or fails, leaves the combination's last answer where it was, so a visitor is shown an old real run (marked as
 * old by the menu's view) and never an empty one.
 */
public class AgentMenuJob {

    private static final Logger log = LoggerFactory.getLogger(AgentMenuJob.class);

    /** Runs one definition with the real engine (the orchestrator; a fake in the tests). */
    @FunctionalInterface
    public interface Runner {
        RunSummary run(ScenarioDefinition scenario);
    }

    /** What the given runs cost in dollars, from the cost ledger by each model's own price. */
    @FunctionalInterface
    public interface Spending {
        double usdOf(Collection<String> runIds);
    }

    /**
     * @param stopped why the job stopped before the end of the table ({@code DAILY_LIMIT}); null when it ran through
     */
    public record Result(int ran, int failed, int skipped, double spentUsd, String stopped) {
    }

    private final AgentTaskCatalog catalog;
    private final ObjectMapper json;
    private final Runner runner;
    private final AgentMenuStore store;
    private final Spending spending;
    private final double dailyLimitUsd;
    private final Clock clock;

    public AgentMenuJob(AgentTaskCatalog catalog, ObjectMapper json, Runner runner, AgentMenuStore store,
                        Spending spending, double dailyLimitUsd, Clock clock) {
        this.catalog = catalog;
        this.json = json;
        this.runner = runner;
        this.store = store;
        this.spending = spending;
        this.dailyLimitUsd = dailyLimitUsd;
        this.clock = clock;
    }

    /** The definition of a combination as it runs: the case's work sent on the path, with the choice applied. */
    public ScenarioDefinition scenarioOf(AgentMenu.Combo combo) {
        ScenarioDefinition scenario = catalog.find(combo.caseKey()).orElseThrow(() -> new IllegalStateException(
                "The agent menu names the case " + combo.caseKey() + ", which is not packaged"))
                .onPath(AgentPaths.sender(combo.path()));
        return combo.choice() == null ? scenario : combo.choice().applyTo(scenario);
    }

    /** The hash of a combination's definition in force, to tell an answer that ran an older one. */
    public String shaOf(AgentMenu.Combo combo) {
        return RunOrchestrator.definitionSha256(json, scenarioOf(combo));
    }

    /** Runs the whole table once. */
    public Result refresh() {
        return refresh(combo -> true);
    }

    /** Runs the combinations of the table the filter takes, once; the day's row records what it ran and spent. */
    public synchronized Result refresh(Predicate<AgentMenu.Combo> only) {
        Instant started = clock.instant();
        LocalDate day = LocalDate.ofInstant(started, ZoneOffset.UTC);
        store.startJob(day, started);
        List<String> runIds = new ArrayList<>();
        int ran = 0;
        int failed = 0;
        int skipped = 0;
        String stopped = null;
        for (AgentMenu.Combo combo : AgentMenu.combos().stream().filter(only).toList()) {
            if (stopped != null) {
                skipped++;
                continue;
            }
            if (spending.usdOf(runIds) >= dailyLimitUsd) {
                stopped = "DAILY_LIMIT";
                skipped++;
                continue;
            }
            try {
                ScenarioDefinition scenario = scenarioOf(combo);
                RunSummary summary = runner.run(scenario);
                if (summary != null && summary.runId() != null) {
                    runIds.add(summary.runId());
                }
                if (summary != null && "COMPLETED".equals(summary.status())) {
                    store.keep(combo.caseKey(), combo.path(), combo.choiceKey(), summary.runId(),
                            RunOrchestrator.definitionSha256(json, scenario), clock.instant());
                    ran++;
                } else {
                    failed++;
                    log.warn("The agent menu's run of {} on {} did not finish: {}", combo.caseKey(), combo.path(),
                            summary == null ? null : summary.status());
                }
            } catch (RuntimeException e) {
                failed++;
                log.error("The agent menu's run of {} on {} failed", combo.caseKey(), combo.path(), e);
            }
        }
        double spent = spending.usdOf(runIds);
        store.finishJob(day, clock.instant(), ran, failed, skipped, spent, stopped);
        return new Result(ran, failed, skipped, spent, stopped);
    }
}
