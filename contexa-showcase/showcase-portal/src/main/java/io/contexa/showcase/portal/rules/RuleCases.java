package io.contexa.showcase.portal.rules;

import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.replay.ReplayStore.ArmRow;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The cases of the rule-limits scene (docs/showcase/화면설계서.md scene 4): for each scenario with a ground truth, the
 * latest complete real run without a forced decision, with what the two rule controls actually looked at and decided
 * on every step and what Contexa did. The screen recomputes the rules from these inputs with the visitor's settings;
 * with the default settings it must reproduce the recorded rule decisions (E-3). Cached for a minute.
 */
public class RuleCases {

    private static final Logger log = LoggerFactory.getLogger(RuleCases.class);

    static final Duration CACHE = Duration.ofMinutes(1);
    /**
     * Copies of A3 and A3T that differ only in how Contexa decides (streamed, or the same export decided
     * asynchronously); the rule controls see the same request, so A3 and A3T stand for them.
     */
    static final Set<String> EXCLUDED = Set.of("A3S", "A3ST", "A3A", "A3TA");
    static final Set<String> CLASSES = Set.of("THREAT", "NORMAL");

    /** One request of a case: the rule controls' inputs and decisions and Contexa's outcome. */
    public record CaseStep(int stepNo, String operation, Instant companyTime, Map<String, Object> c1Facts,
                           String c1Outcome, String c1Rule, Map<String, Object> c2Facts, String c2Outcome,
                           String c2Rule, String contexaOutcome, String contexaVerdict) {
    }

    public record Case(String scenario, String classification, Map<String, String> title, String runId,
                       Instant finishedAt, List<CaseStep> steps) {
    }

    public record View(Instant computedAt, List<Case> cases) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final ReplayStore store;
    private final ReplayViews views;
    private final ScenarioCatalog scenarios;
    private final Clock clock;
    private View cached;

    public RuleCases(NamedParameterJdbcTemplate jdbc, ReplayStore store, ReplayViews views, ScenarioCatalog scenarios,
                     Clock clock) {
        this.jdbc = jdbc;
        this.store = store;
        this.views = views;
        this.scenarios = scenarios;
        this.clock = clock;
    }

    public synchronized View view() {
        Instant now = clock.instant();
        if (cached == null || !now.isBefore(cached.computedAt().plus(CACHE))) {
            cached = compute(now);
        }
        return cached;
    }

    private View compute(Instant now) {
        List<Case> cases = new ArrayList<>();
        for (ScenarioDefinition scenario : scenarios.all()) {
            String classification = scenario.oracle().classification();
            if (EXCLUDED.contains(scenario.key()) || !CLASSES.contains(classification)) {
                continue;
            }
            latest(scenario).ifPresent(cases::add);
        }
        return new View(now, List.copyOf(cases));
    }

    /** The newest complete run of the current scenario version, skipping one whose steps cannot all be read. */
    private Optional<Case> latest(ScenarioDefinition scenario) {
        List<Map<String, Object>> runs = jdbc.queryForList("""
                        select run_id, finished_at from run
                         where scenario_key = :key and scenario_version = :version and status = 'COMPLETED'
                           and forced_action is null
                         order by finished_at desc limit 5""",
                new MapSqlParameterSource("key", scenario.key()).addValue("version", scenario.version()));
        for (Map<String, Object> row : runs) {
            String runId = (String) row.get("run_id");
            try {
                if (store.stepCount(runId) != scenario.steps().size()) {
                    continue;
                }
                List<CaseStep> steps = new ArrayList<>();
                for (int stepNo = 1; stepNo <= scenario.steps().size(); stepNo++) {
                    steps.add(step(runId, stepNo));
                }
                Instant finished = row.get("finished_at") instanceof Timestamp stamp ? stamp.toInstant() : null;
                return Optional.of(new Case(scenario.key(), scenario.oracle().classification(), scenario.title(),
                        runId, finished, List.copyOf(steps)));
            } catch (RuntimeException e) {
                log.error("Rule case could not be read: scenario={}, runId={}", scenario.key(), runId, e);
            }
        }
        return Optional.empty();
    }

    private CaseStep step(String runId, int stepNo) {
        Map<String, ArmRow> arms = store.arms(runId, stepNo);
        ReplayView.StepResult result = views.step(runId, stepNo);
        ReplayView.Layer c1 = layer(result, "C1");
        ReplayView.Layer c2 = layer(result, "C2");
        ReplayView.Layer d = layer(result, "D");
        ArmRow arm = arms.get("C1");
        return new CaseStep(stepNo, arm.operation(), arm.companyTime(), c1.ruleFacts(), c1.outcome(), c1.ruleId(),
                c2.ruleFacts(), c2.outcome(), c2.ruleId(), d.outcome(), d.verdict());
    }

    private static ReplayView.Layer layer(ReplayView.StepResult result, String control) {
        return result.layers().stream().filter(layer -> control.equals(layer.control())).findFirst()
                .orElseThrow(() -> new IllegalStateException("No result of " + control));
    }
}
