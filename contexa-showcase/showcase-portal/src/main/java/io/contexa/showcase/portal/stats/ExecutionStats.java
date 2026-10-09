package io.contexa.showcase.portal.stats;

import io.contexa.showcase.portal.replay.OutcomeSignature;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.stats.StatsView.LayerStats;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Counts the execution statistics (deck p.17, docs/showcase/P5-설계.md section 3) from the stored runs. Misses and
 * false blocks come from the one scoring rule ({@link RunScores}, docs/showcase/데모-재설계.md 5.0): each control's
 * business result over the whole case, against the ground truth of the definition the run executed. Runs without a
 * ground truth are counted apart. The view is cached for a minute because the page is public.
 */
public class ExecutionStats {

    static final Duration CACHE = Duration.ofMinutes(1);
    static final String COUNTED_RUNS = "r.forced_action is null and r.status = 'COMPLETED'";

    private final NamedParameterJdbcTemplate jdbc;
    private final RunScores scores;
    private final Clock clock;
    private StatsView cached;

    public ExecutionStats(NamedParameterJdbcTemplate jdbc, RunScores scores, Clock clock) {
        this.jdbc = jdbc;
        this.scores = scores;
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
        List<String> counted = jdbc.getJdbcTemplate().queryForList(
                "select r.run_id from run r where " + COUNTED_RUNS, String.class);
        List<RunScore> scored = scores.scoreAll(counted);
        return new StatsView(now, runs(now), decisionTime(), engineActions(), unresolved(), agreement(),
                scope(scored), layers(scored), spec(), jdbc.getJdbcTemplate().queryForObject(
                "select count(distinct r.spec_hash) from run r where " + COUNTED_RUNS, Long.class),
                jdbc.getJdbcTemplate().queryForObject("select count(*) from run_release x join run r on r.run_id = "
                        + "x.run_id where " + COUNTED_RUNS, Long.class));
    }

    private StatsView.Runs runs(Instant now) {
        return jdbc.queryForObject("""
                        select count(*) filter (where r.status = 'COMPLETED') as completed,
                               count(*) filter (where r.status = 'FAILED') as failed,
                               count(*) filter (where r.status = 'COMPLETED' and r.started_at >= :today) as today,
                               count(*) filter (where r.status = 'COMPLETED' and r.live_run)
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

    private static StatsView.Scope scope(List<RunScore> scored) {
        long threat = scored.stream().filter(score -> score.truth().threat()).count();
        long normal = scored.stream().filter(score -> score.truth().normal()).count();
        return new StatsView.Scope(threat, normal, scored.size() - threat - normal);
    }

    /** Each control's business result over the whole case of every counted run with a ground truth. */
    static List<LayerStats> layers(List<RunScore> scored) {
        List<LayerStats> layers = new ArrayList<>();
        for (String control : OutcomeSignature.CONTROLS) {
            long[] threat = new long[6];
            long[] normal = new long[5];
            for (RunScore score : scored) {
                CaseScore result = score.business().get(control);
                if (result == null) {
                    continue;
                }
                if (score.truth().threat()) {
                    threat[0]++;
                    threat[5] += result.exposedItems();
                    switch (result.result()) {
                        case STOPPED -> threat[1]++;
                        case PARTLY_STOPPED -> threat[2]++;
                        case MISSED -> threat[3]++;
                        default -> threat[4]++;
                    }
                } else if (score.truth().normal()) {
                    normal[0]++;
                    switch (result.result()) {
                        case PASSED -> normal[1]++;
                        case PASSED_AFTER_CHECK -> normal[2]++;
                        case HALTED -> normal[3]++;
                        default -> normal[4]++;
                    }
                }
            }
            layers.add(new LayerStats(control,
                    new StatsView.Threat(threat[0], threat[1], threat[2], threat[3], threat[4], threat[5]),
                    new StatsView.Normal(normal[0], normal[1], normal[2], normal[3], normal[4])));
        }
        return layers;
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
