package io.contexa.showcase.portal.stats;

import io.contexa.showcase.portal.replay.OutcomeSignature;
import io.contexa.showcase.portal.replay.PairCatalog;
import io.contexa.showcase.portal.replay.PairDefinition;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.stats.StatsView.LayerStats;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeMap;

/**
 * Counts the execution statistics (deck p.17, docs/showcase/P5-설계.md section 3) from the stored runs. A miss or a
 * false block is read the way screen 1 shows a scene: the business outcome of each control at the decisive step,
 * which is the pair's featured step for a scenario that plays a pair scene and the last step otherwise. Only
 * scenarios with a ground truth (threat or normal) are counted there. The view is cached for a minute because the
 * page is public.
 */
public class ExecutionStats {

    static final Duration CACHE = Duration.ofMinutes(1);
    static final String COUNTED_RUNS = "r.forced_action is null and r.status = 'COMPLETED'";

    enum Result { DELIVERED, STOPPED, CHALLENGED, HELD_FOR_REVIEW, UNRESOLVED }

    private final NamedParameterJdbcTemplate jdbc;
    private final ScenarioCatalog scenarios;
    private final PairCatalog pairs;
    private final Clock clock;
    private StatsView cached;

    public ExecutionStats(NamedParameterJdbcTemplate jdbc, ScenarioCatalog scenarios, PairCatalog pairs, Clock clock) {
        this.jdbc = jdbc;
        this.scenarios = scenarios;
        this.pairs = pairs;
        this.clock = clock;
    }

    public synchronized StatsView view() {
        Instant now = clock.instant();
        if (cached == null || !now.isBefore(cached.computedAt().plus(CACHE))) {
            cached = compute(now);
        }
        return cached;
    }

    StatsView compute(Instant now) {
        Map<String, Integer> decisiveSteps = decisiveSteps();
        Map<String, String> classes = new HashMap<>();
        scenarios.all().forEach(scenario -> classes.put(scenario.key(), scenario.oracle().classification()));
        return new StatsView(now, runs(now), decisionTime(), engineActions(), unresolved(), agreement(),
                scope(classes), layers(decisiveSteps, classes), spec(), jdbc.getJdbcTemplate().queryForObject(
                "select count(distinct r.spec_hash) from run r where " + COUNTED_RUNS, Long.class));
    }

    /** The decisive step of every scenario with a ground truth. */
    Map<String, Integer> decisiveSteps() {
        Map<String, Integer> featured = new HashMap<>();
        for (PairDefinition pair : pairs.all()) {
            pair.scenes().forEach(scene -> featured.put(scene.scenario(), scene.featuredStep()));
        }
        Map<String, Integer> steps = new TreeMap<>();
        for (ScenarioDefinition scenario : scenarios.all()) {
            String classification = scenario.oracle().classification();
            if ("THREAT".equals(classification) || "NORMAL".equals(classification)) {
                steps.put(scenario.key(), featured.getOrDefault(scenario.key(), scenario.steps().size()));
            }
        }
        return steps;
    }

    private StatsView.Runs runs(Instant now) {
        return jdbc.queryForObject("""
                        select count(*) filter (where r.status = 'COMPLETED') as completed,
                               count(*) filter (where r.status = 'FAILED') as failed,
                               count(*) filter (where r.status = 'COMPLETED' and r.started_at >= :today) as today,
                               count(*) filter (where r.status = 'COMPLETED' and r.live_visitor_hash is not null)
                                   as live,
                               min(r.started_at) filter (where r.status = 'COMPLETED') as first_at,
                               max(r.started_at) filter (where r.status = 'COMPLETED') as last_at
                          from run r where r.forced_action is null""",
                new MapSqlParameterSource("today", Timestamp.from(now.truncatedTo(ChronoUnit.DAYS))),
                (rs, n) -> new StatsView.Runs(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4),
                        instant(rs.getTimestamp(5)), instant(rs.getTimestamp(6))));
    }

    private StatsView.DecisionTime decisionTime() {
        return jdbc.getJdbcTemplate().queryForObject("""
                select count(*),
                       percentile_cont(0.5) within group (order by d.total_analysis_ms),
                       percentile_cont(0.95) within group (order by d.total_analysis_ms)
                  from run_decision d join run r on r.run_id = d.run_id
                 where %s and d.final_action is not null and not coalesce(d.unresolved, false)
                   and d.total_analysis_ms is not null""".formatted(COUNTED_RUNS),
                (rs, n) -> new StatsView.DecisionTime(rs.getLong(1), rounded(rs.getObject(2)),
                        rounded(rs.getObject(3))));
    }

    private Map<String, Long> engineActions() {
        Map<String, Long> actions = new LinkedHashMap<>();
        for (String action : List.of("ALLOW", "CHALLENGE", "BLOCK", "ESCALATE")) {
            actions.put(action, 0L);
        }
        jdbc.getJdbcTemplate().query("""
                select d.final_action, count(*)
                  from run_decision d join run r on r.run_id = d.run_id
                 where %s and d.final_action is not null and not coalesce(d.unresolved, false)
                 group by d.final_action""".formatted(COUNTED_RUNS),
                rs -> {
                    actions.put(rs.getString(1), rs.getLong(2));
                });
        return actions;
    }

    private StatsView.Unresolved unresolved() {
        return jdbc.getJdbcTemplate().queryForObject("""
                select count(*) filter (where coalesce(d.unresolved, false)),
                       count(*) filter (where d.applied = 'NONE')
                  from run_decision d join run r on r.run_id = d.run_id
                 where %s""".formatted(COUNTED_RUNS),
                (rs, n) -> new StatsView.Unresolved(rs.getLong(1), rs.getLong(2)));
    }

    private StatsView.Agreement agreement() {
        List<StatsView.Recording> recordings = jdbc.getJdbcTemplate().query("""
                        select pair_key, scene, agreeing, repetitions, recorded_at
                          from replay_record where status = 'PUBLISHED' order by pair_key, scene""",
                (rs, n) -> new StatsView.Recording(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getInt(4),
                        instant(rs.getTimestamp(5))));
        return new StatsView.Agreement(recordings.stream().mapToLong(StatsView.Recording::agreeing).sum(),
                recordings.stream().mapToLong(StatsView.Recording::repetitions).sum(), recordings);
    }

    private StatsView.Scope scope(Map<String, String> classes) {
        long[] counts = new long[3];
        jdbc.getJdbcTemplate().query("select r.scenario_key, count(*) from run r where " + COUNTED_RUNS
                + " group by r.scenario_key", rs -> {
                    String classification = classes.get(rs.getString(1));
                    int slot = "THREAT".equals(classification) ? 0 : "NORMAL".equals(classification) ? 1 : 2;
                    counts[slot] += rs.getLong(2);
                });
        return new StatsView.Scope(counts[0], counts[1], counts[2]);
    }

    /** Each control's result at the decisive step of every counted run with a ground truth. */
    private List<LayerStats> layers(Map<String, Integer> decisiveSteps, Map<String, String> classes) {
        Map<String, Map<String, Result>> results = new HashMap<>();
        Map<String, String> runScenario = new HashMap<>();
        if (!decisiveSteps.isEmpty()) {
            MapSqlParameterSource parameters = new MapSqlParameterSource();
            StringJoiner values = new StringJoiner(", ");
            int i = 0;
            for (Map.Entry<String, Integer> entry : decisiveSteps.entrySet()) {
                values.add("(cast(:k" + i + " as varchar), cast(:s" + i + " as integer))");
                parameters.addValue("k" + i, entry.getKey()).addValue("s" + i, entry.getValue());
                i++;
            }
            jdbc.query("""
                    select r.run_id, r.scenario_key, a.control, a.outcome, a.http_status, d.unresolved
                      from run r
                      join (values %s) as k(scenario_key, step_no) on k.scenario_key = r.scenario_key
                      join run_arm_result a on a.run_id = r.run_id and a.step_no = k.step_no
                      left join run_decision d on a.control = 'D' and d.run_id = a.run_id and d.step_no = a.step_no
                     where %s""".formatted(values, COUNTED_RUNS), parameters, rs -> {
                runScenario.put(rs.getString(1), rs.getString(2));
                results.computeIfAbsent(rs.getString(1), run -> new HashMap<>()).put(rs.getString(3),
                        result(rs.getString(3), rs.getString(4), (Integer) rs.getObject(5),
                                Boolean.TRUE.equals(rs.getObject(6))));
            });
        }
        List<LayerStats> layers = new ArrayList<>();
        for (String control : OutcomeSignature.CONTROLS) {
            long[] threat = new long[4];
            long[] normal = new long[5];
            results.forEach((run, arms) -> {
                Result result = arms.getOrDefault(control, Result.UNRESOLVED);
                if ("THREAT".equals(classes.get(runScenario.get(run)))) {
                    threat[0]++;
                    threat[result == Result.DELIVERED ? 1 : result == Result.UNRESOLVED ? 3 : 2]++;
                } else {
                    normal[0]++;
                    normal[switch (result) {
                        case DELIVERED -> 1;
                        case CHALLENGED -> 2;
                        case UNRESOLVED -> 4;
                        default -> 3;
                    }]++;
                }
            });
            layers.add(new LayerStats(control, new StatsView.Threat(threat[0], threat[1], threat[2], threat[3]),
                    new StatsView.Normal(normal[0], normal[1], normal[2], normal[3], normal[4])));
        }
        return layers;
    }

    /**
     * The business result of one control at one step, as screen 1 reads it: control D's 401 is the extra check and
     * its 423 the review hold; a failed request, or an engine decision that could not be completed, is unresolved.
     */
    static Result result(String control, String outcome, Integer httpStatus, boolean engineUnresolved) {
        if ("ERROR".equals(outcome) || ("D".equals(control) && engineUnresolved && !"DELIVERED".equals(outcome))) {
            return Result.UNRESOLVED;
        }
        if ("DELIVERED".equals(outcome)) {
            return Result.DELIVERED;
        }
        if ("D".equals(control) && httpStatus != null && httpStatus == 401) {
            return Result.CHALLENGED;
        }
        if ("D".equals(control) && httpStatus != null && httpStatus == 423) {
            return Result.HELD_FOR_REVIEW;
        }
        return Result.STOPPED;
    }

    private StatsView.Spec spec() {
        return jdbc.getJdbcTemplate().query("""
                        select s.spec_hash, s.code_commit, s.engine_version, s.effective_mode, s.chat_model,
                               s.embedding_model, s.time_zone
                          from run r join execution_spec s on s.spec_hash = r.spec_hash
                         where %s order by r.started_at desc limit 1""".formatted(COUNTED_RUNS),
                (rs, n) -> new StatsView.Spec(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6), rs.getString(7)))
                .stream().findFirst().orElse(null);
    }

    private static Long rounded(Object value) {
        return value instanceof Number number ? Math.round(number.doubleValue()) : null;
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
