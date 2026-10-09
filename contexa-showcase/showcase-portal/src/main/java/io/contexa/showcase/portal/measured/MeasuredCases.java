package io.contexa.showcase.portal.measured;

import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * The runs of one case in the current measurement as the screens' "measured N times" lines show them (E1-5 and E2-5 of
 * docs/showcase/화면설계서-v2-구현계획.md, V-17): Contexa's result of each run, its analysis time of the first request,
 * what it let out and the time to resume after a check, with the counts and ranges the sentences need. Everything is
 * counted here from the stored runs, so a screen only writes the values down.
 */
public class MeasuredCases {

    static final Duration CACHE = Duration.ofMinutes(1);
    /** The request the lines speak of; the analysis time and the check are read at it. */
    static final int FIRST_REQUEST = 1;

    public record Range(long min, long max) {
    }

    /**
     * @param result        Contexa's business result over the run
     * @param engineAction  Contexa's decision of the first request; null without one
     * @param analysisMs    the engine's analysis time of the first request; null without a decision
     * @param exposedItems  what Contexa let out over the run
     * @param releaseMillis from the additional check at the first request to the re-issued request; null when there was
     *                      no answered check
     * @param responseMs    how long Contexa's application took to answer the first request (the time a synchronous
     *                      decision holds the response); null when the arm recorded none
     */
    public record MeasuredRun(String runId, Instant startedAt, String result, String engineAction, Long analysisMs,
                              long exposedItems, String reissueOutcome, Long releaseMillis, Long responseMs) {
    }

    /**
     * The latest measured run of the case in which the additional check was answered and the original request went out
     * again (E2-7 of the plan, D-31), from any setting: a screen whose visitor met no check shows this record and says
     * whether it belongs to the current setting.
     *
     * @param current the run belongs to the measurement setting the benchmark shows by default
     */
    public record Resumed(String runId, Instant startedAt, String settingHash, boolean current) {
    }

    /**
     * @param results    how many runs ended with each Contexa result
     * @param allSame    every run ended with the same Contexa result
     * @param analysisMs the shortest and longest analysis time of the first request; null without a decision
     * @param resumed    the latest answered and re-issued check of the case in a measurement; null when none exists
     * @param responseMs the shortest and longest time Contexa's application took to answer the first request
     * @param middleRun  the run whose analysis time is in the middle (the lower middle of an even count), the one a
     *                   screen shows as the example of the measurement; null without a decision
     */
    public record View(String caseKey, String settingHash, String protocolId, int runs, Map<String, Long> results,
                       boolean allSame, Range analysisMs, Range exposedItems, List<MeasuredRun> list,
                       Resumed resumed, Range responseMs, String middleRun) {
    }

    private record Cached(Optional<View> view, Instant at) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final RunScores scores;
    private final Supplier<Optional<String>> currentSetting;
    private final Clock clock;
    private final Map<String, Cached> cache = new HashMap<>();

    /** @param currentSetting the measurement setting the benchmark shows by default */
    public MeasuredCases(NamedParameterJdbcTemplate jdbc, RunScores scores, Supplier<Optional<String>> currentSetting,
                         Clock clock) {
        this.jdbc = jdbc;
        this.scores = scores;
        this.currentSetting = currentSetting;
        this.clock = clock;
    }

    /** The case's runs in the latest measurement of the current setting; empty without one. */
    public synchronized Optional<View> view(String caseKey) {
        Optional<String> setting = currentSetting.get();
        if (setting.isEmpty()) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        String key = setting.get() + "|" + caseKey;
        Cached cached = cache.get(key);
        if (cached == null || !now.isBefore(cached.at().plus(CACHE))) {
            cached = new Cached(compute(setting.get(), caseKey), now);
            cache.put(key, cached);
        }
        return cached.view();
    }

    private Optional<View> compute(String setting, String caseKey) {
        MapSqlParameterSource parameters = new MapSqlParameterSource("setting", setting).addValue("case", caseKey);
        List<String> protocols = jdbc.queryForList("""
                select r.protocol_id from run r
                 where r.setting_hash = :setting and r.scenario_key = :case and r.protocol_id is not null
                   and r.status = 'COMPLETED' and r.forced_action is null
                 order by r.started_at desc limit 1""", parameters, String.class);
        if (protocols.isEmpty()) {
            return Optional.empty();
        }
        Map<String, Instant> started = new LinkedHashMap<>();
        jdbc.query("""
                        select r.run_id, r.started_at from run r
                         where r.protocol_id = :protocol and r.setting_hash = :setting and r.scenario_key = :case
                           and r.status = 'COMPLETED' and r.forced_action is null
                         order by r.started_at""", parameters.addValue("protocol", protocols.get(0)),
                rs -> {
                    Timestamp at = rs.getTimestamp(2);
                    started.put(rs.getString(1), at == null ? null : at.toInstant());
                });
        Map<String, String> actions = new HashMap<>();
        Map<String, Long> analysis = new HashMap<>();
        jdbc.query("""
                        select d.run_id, d.final_action, d.total_analysis_ms from run_decision d
                         where d.run_id = any(:runs) and d.step_no = :step""",
                new MapSqlParameterSource("runs", started.keySet().toArray(new String[0]))
                        .addValue("step", FIRST_REQUEST), rs -> {
                    actions.put(rs.getString(1), rs.getString(2));
                    long ms = rs.getLong(3);
                    if (!rs.wasNull()) {
                        analysis.put(rs.getString(1), ms);
                    }
                });
        Map<String, Long> response = new HashMap<>();
        jdbc.query("""
                        select a.run_id, a.elapsed_ms from run_arm_result a
                         where a.run_id = any(:runs) and a.step_no = :step and a.control = 'D'
                           and a.elapsed_ms is not null""",
                new MapSqlParameterSource("runs", started.keySet().toArray(new String[0]))
                        .addValue("step", FIRST_REQUEST), rs -> {
                    response.put(rs.getString(1), rs.getLong(2));
                });
        Map<String, RunScore> scored = new HashMap<>();
        scores.scoreAll(started.keySet()).forEach(score -> scored.put(score.runId(), score));
        List<MeasuredRun> runs = new ArrayList<>();
        Map<String, Long> results = new TreeMap<>();
        for (Map.Entry<String, Instant> run : started.entrySet()) {
            RunScore score = scored.get(run.getKey());
            CaseScore contexa = score == null ? null : score.business().get("D");
            String result = contexa == null ? "NONE" : contexa.result().name();
            RunScores.Check check = score == null ? null : score.checks().stream()
                    .filter(candidate -> candidate.stepNo() == FIRST_REQUEST).findFirst().orElse(null);
            runs.add(new MeasuredRun(run.getKey(), run.getValue(), result, actions.get(run.getKey()),
                    analysis.get(run.getKey()), contexa == null ? 0 : contexa.exposedItems(),
                    check == null ? null : check.reissueOutcome(), check == null ? null : check.releaseMillis(),
                    response.get(run.getKey())));
            results.merge(result, 1L, Long::sum);
        }
        return Optional.of(new View(caseKey, setting, protocols.get(0), runs.size(), results, results.size() == 1,
                range(runs.stream().map(MeasuredRun::analysisMs).toList()),
                range(runs.stream().map(MeasuredRun::exposedItems).toList()), runs, resumed(setting, caseKey),
                range(runs.stream().map(MeasuredRun::responseMs).toList()), middle(runs)));
    }

    /** The run whose analysis time is in the middle of the decided runs (the lower middle of an even count). */
    static String middle(List<MeasuredRun> runs) {
        List<MeasuredRun> decided = runs.stream().filter(run -> run.analysisMs() != null)
                .sorted(Comparator.comparingLong(MeasuredRun::analysisMs)).toList();
        return decided.isEmpty() ? null : decided.get((decided.size() - 1) / 2).runId();
    }

    private Resumed resumed(String setting, String caseKey) {
        List<Resumed> found = jdbc.query("""
                        select r.run_id, r.started_at, r.setting_hash from run_challenge c
                          join run r on r.run_id = c.run_id
                         where r.scenario_key = :case and r.protocol_id is not null and r.status = 'COMPLETED'
                           and r.forced_action is null and c.step_no = :step and c.answered
                           and c.reissue_outcome is not null
                         order by r.started_at desc limit 1""",
                new MapSqlParameterSource("case", caseKey).addValue("step", FIRST_REQUEST),
                (rs, row) -> {
                    Timestamp at = rs.getTimestamp(2);
                    String hash = rs.getString(3);
                    return new Resumed(rs.getString(1), at == null ? null : at.toInstant(), hash,
                            setting.equals(hash));
                });
        return found.isEmpty() ? null : found.get(0);
    }

    /** The smallest and largest of the values present; null when none is. */
    static Range range(List<Long> values) {
        List<Long> present = values.stream().filter(Objects::nonNull).toList();
        if (present.isEmpty()) {
            return null;
        }
        return new Range(present.stream().mapToLong(Long::longValue).min().orElseThrow(),
                present.stream().mapToLong(Long::longValue).max().orElseThrow());
    }
}
