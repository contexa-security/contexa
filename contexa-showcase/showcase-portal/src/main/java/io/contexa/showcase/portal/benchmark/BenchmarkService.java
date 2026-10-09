package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.replay.OutcomeSignature;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scoring.JudgmentTiming;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.scoring.Scoring.Truth;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Counts the benchmark of one engine setting (docs/showcase/데모-재설계.md 5A.2, W5-1 to W5-4) from the stored runs of
 * its measurement protocols, scored by the one scoring rule ({@link RunScores}). Visitors' runs and opinions are counted
 * apart. Cached for a minute per setting because the page is public.
 */
public class BenchmarkService {

    static final Duration CACHE = Duration.ofMinutes(1);
    /** Visitors' assessments count only after this delay (J-5); the lab's peer view uses the same rule. */
    public static final int ASSESSMENT_DELAY_HOURS = 1;
    static final List<String> NOTICES = List.of("METHODS_NOT_PRODUCTS", "STRUCTURAL_BLIND_SPOTS",
            "C2_WRITTEN_FOR_THE_CASES", "PROTOCOL_RUNS_ONLY", "VISITORS_APART");
    private static final String COUNTED = "r.status = 'COMPLETED' and r.forced_action is null";
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    /** Price per million tokens: input, cached input, output. */
    public record Price(double input, double cachedInput, double output) {
    }

    private record Cached(BenchmarkView view, Instant at) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final RunScores scores;
    private final ScenarioCatalog catalog;
    private final ObjectMapper json;
    private final Map<String, Price> prices;
    private final String priceSource;
    private final Clock clock;
    private final Map<String, Cached> cache = new HashMap<>();

    public BenchmarkService(NamedParameterJdbcTemplate jdbc, RunScores scores, ScenarioCatalog catalog,
                            ObjectMapper json, Map<String, Price> prices, String priceSource, Clock clock) {
        this.jdbc = jdbc;
        this.scores = scores;
        this.catalog = catalog;
        this.json = json;
        this.prices = Map.copyOf(prices);
        this.priceSource = priceSource;
        this.clock = clock;
    }

    /** Parses "model=input/cached/output;model=..." as configured. */
    public static Map<String, Price> prices(String configured) {
        Map<String, Price> parsed = new LinkedHashMap<>();
        for (String entry : configured.split(";")) {
            String[] parts = entry.trim().split("=");
            if (parts.length != 2) {
                continue;
            }
            String[] values = parts[1].split("/");
            parsed.put(parts[0].trim(), new Price(Double.parseDouble(values[0]), Double.parseDouble(values[1]),
                    Double.parseDouble(values[2])));
        }
        return parsed;
    }

    /** The benchmark of a measurement setting; the latest one when none is named. */
    public synchronized Optional<BenchmarkView> view(String settingHash) {
        List<BenchmarkView.Spec> specs = specs();
        Optional<BenchmarkView.Spec> spec = settingHash == null ? specs.stream().findFirst()
                : specs.stream().filter(candidate -> candidate.settingHash().equals(settingHash)).findFirst();
        if (settingHash != null && spec.isEmpty()) {
            return Optional.empty();
        }
        String key = spec.map(BenchmarkView.Spec::settingHash).orElse("");
        Instant now = clock.instant();
        Cached cached = cache.get(key);
        if (cached != null && now.isBefore(cached.at().plus(CACHE))) {
            return Optional.of(cached.view());
        }
        BenchmarkView view = compute(now, specs, spec.orElse(null));
        cache.put(key, new Cached(view, now));
        return Optional.of(view);
    }

    /**
     * The raw records behind a setting's scores (bench-1 "download the raw data"): every counted protocol run of the
     * setting scored by the one rule, oldest first; the latest setting when none is named.
     *
     * @param settingHash the setting the runs belong to
     * @param runs        each run's score as {@code GET /api/runs/{runId}/score} returns it
     */
    public record Raw(String settingHash, List<RunScore> runs) {
    }

    public Optional<Raw> raw(String settingHash) {
        List<BenchmarkView.Spec> specs = specs();
        Optional<BenchmarkView.Spec> spec = settingHash == null ? specs.stream().findFirst()
                : specs.stream().filter(candidate -> candidate.settingHash().equals(settingHash)).findFirst();
        if (spec.isEmpty()) {
            return Optional.empty();
        }
        List<String> runIds = jdbc.queryForList("select r.run_id from run r where r.protocol_id is not null and "
                        + COUNTED + " and r.setting_hash = :spec order by r.started_at",
                new MapSqlParameterSource("spec", spec.get().settingHash()), String.class);
        return Optional.of(new Raw(spec.get().settingHash(), scores.scoreAll(runIds)));
    }

    BenchmarkView compute(Instant now, List<BenchmarkView.Spec> specs, BenchmarkView.Spec spec) {
        long withoutSetting = count("select count(*) from run r where r.protocol_id is not null and " + COUNTED
                + " and r.setting_hash is null", new MapSqlParameterSource());
        if (spec == null) {
            return new BenchmarkView(now, NOTICES, specs, null, new BenchmarkView.Scope(0, 0, 0, 0, 0, List.of()),
                    List.of(), List.of(), List.of(), 0, List.of(), riskJudged(List.of()), judgmentTiming(List.of()),
                    null,
                    observations(null), withoutSetting);
        }
        MapSqlParameterSource bySpec = new MapSqlParameterSource("spec", spec.settingHash());
        List<String> runIds = jdbc.queryForList("select r.run_id from run r where r.protocol_id is not null and "
                + COUNTED + " and r.setting_hash = :spec", bySpec, String.class);
        List<RunScore> scored = scores.scoreAll(runIds);
        long attack = scored.stream().filter(score -> score.truth().threat()).count();
        long normal = scored.stream().filter(score -> score.truth().normal()).count();
        List<BenchmarkView.Protocol> protocols = jdbc.query("""
                        select p.protocol_id, p.repeat, jsonb_array_length(p.cases), p.started_at, p.finished_at,
                               count(r.run_id) filter (where r.status = 'COMPLETED' and r.forced_action is null),
                               count(r.run_id) filter (where r.status <> 'COMPLETED'),
                               count(r.run_id) filter (where r.status = 'COMPLETED' and r.forced_action is not null)
                          from measurement_protocol p left join run r on r.protocol_id = p.protocol_id
                         where exists (select 1 from run s where s.protocol_id = p.protocol_id
                                          and s.setting_hash = :spec)
                         group by p.protocol_id, p.repeat, p.cases, p.started_at, p.finished_at
                         order by p.started_at""", bySpec,
                (rs, n) -> new BenchmarkView.Protocol(rs.getString(1), rs.getInt(2), rs.getInt(3),
                        (long) rs.getInt(2) * rs.getInt(3), instant(rs.getTimestamp(4)), instant(rs.getTimestamp(5)),
                        rs.getLong(6), rs.getLong(7), rs.getLong(8)));
        BenchmarkView.Scope scope = new BenchmarkView.Scope(scored.size(), attack, normal,
                scored.size() - attack - normal,
                (int) scored.stream().map(RunScore::scenarioKey).distinct().count(), protocols);
        return new BenchmarkView(now, NOTICES, specs, spec, scope, controls(scored), cases(scored),
                wrongRuns(scored), unresolvedRuns(scored), suites(scored), riskJudged(scored), judgmentTiming(scored),
                engine(runIds, spec),
                observations(spec.settingHash()), withoutSetting);
    }

    /**
     * The measurement settings with protocol runs, latest first. The fields a setting fixes are the same in every
     * specification of its runs, so any of them states them; the templates and prompt hashes are listed.
     */
    private List<BenchmarkView.Spec> specs() {
        return jdbc.query("""
                        select r.setting_hash, min(s.chat_model), min(s.model_settings::text), min(s.code_commit),
                               min(s.engine_version), min(s.rule_version), min(coalesce(s.contract_version, '')),
                               coalesce(string_agg(distinct r.template_id, ','), ''),
                               coalesce(string_agg(distinct t.learned_under, ','), ''),
                               coalesce(string_agg(distinct s.prompt_hash, ','), ''),
                               count(r.run_id), min(r.started_at), max(r.started_at)
                          from run r join execution_spec s on s.spec_hash = r.spec_hash
                          left join engine_template t on t.template_id = r.template_id
                         where r.protocol_id is not null and r.setting_hash is not null and %s
                         group by r.setting_hash
                         order by max(r.started_at) desc""".formatted(COUNTED), new MapSqlParameterSource(),
                (rs, n) -> new BenchmarkView.Spec(rs.getString(1), rs.getString(2), map(rs.getString(3)),
                        rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), split(rs.getString(8)),
                        split(rs.getString(9)), split(rs.getString(10)), rs.getLong(11),
                        instant(rs.getTimestamp(12)), instant(rs.getTimestamp(13))));
    }

    private static List<String> split(String joined) {
        return joined == null || joined.isBlank() ? List.of() : List.of(joined.split(","));
    }

    static List<BenchmarkView.ControlScore> controls(List<RunScore> scored) {
        List<BenchmarkView.ControlScore> controls = new ArrayList<>();
        for (String control : OutcomeSignature.CONTROLS) {
            long attackResolved = 0;
            long stopped = 0;
            long stoppedAny = 0;
            long attackUnresolved = 0;
            long exposed = 0;
            long normalResolved = 0;
            long halted = 0;
            long checked = 0;
            long normalUnresolved = 0;
            Map<String, long[]> attackByCase = new TreeMap<>();
            Map<String, long[]> attackAnyByCase = new TreeMap<>();
            Map<String, long[]> normalByCase = new TreeMap<>();
            for (RunScore score : scored) {
                CaseScore result = score.business().get(control);
                if (result == null) {
                    continue;
                }
                if (score.truth().threat()) {
                    exposed += result.exposedItems();
                    if (result.result() == BusinessResult.UNRESOLVED) {
                        attackUnresolved++;
                        continue;
                    }
                    attackResolved++;
                    long[] cell = attackByCase.computeIfAbsent(score.scenarioKey(), key -> new long[2]);
                    long[] anyCell = attackAnyByCase.computeIfAbsent(score.scenarioKey(), key -> new long[2]);
                    cell[1]++;
                    anyCell[1]++;
                    if (result.result() == BusinessResult.STOPPED) {
                        stopped++;
                        cell[0]++;
                    }
                    if (result.result() == BusinessResult.STOPPED || result.result() == BusinessResult.PARTLY_STOPPED) {
                        stoppedAny++;
                        anyCell[0]++;
                    }
                } else if (score.truth().normal()) {
                    if (result.result() == BusinessResult.UNRESOLVED) {
                        normalUnresolved++;
                        continue;
                    }
                    normalResolved++;
                    long[] cell = normalByCase.computeIfAbsent(score.scenarioKey(), key -> new long[2]);
                    cell[1]++;
                    if (result.result() == BusinessResult.HALTED) {
                        halted++;
                        cell[0]++;
                    }
                    if (result.result() == BusinessResult.PASSED_AFTER_CHECK) {
                        checked++;
                    }
                }
            }
            controls.add(new BenchmarkView.ControlScore(control, rate(stopped, attackResolved),
                    rate(stoppedAny, attackResolved), macro(attackByCase), macro(attackAnyByCase),
                    rate(halted, normalResolved),
                    rate(checked, normalResolved), macro(normalByCase), attackUnresolved, normalUnresolved,
                    exposed));
        }
        return controls;
    }

    private List<BenchmarkView.CaseRow> cases(List<RunScore> scored) {
        Map<String, List<RunScore>> byCase = new TreeMap<>();
        scored.forEach(score -> byCase.computeIfAbsent(score.scenarioKey(), key -> new ArrayList<>()).add(score));
        Map<String, List<String>> hashes = new HashMap<>();
        if (!scored.isEmpty()) {
            jdbc.query("""
                            select scenario_key, scenario_sha256 from run
                             where run_id = any(:runs) and scenario_sha256 is not null
                             group by scenario_key, scenario_sha256 order by scenario_key, scenario_sha256""",
                    new MapSqlParameterSource("runs", scored.stream().map(RunScore::runId).toArray(String[]::new)),
                    rs -> {
                        hashes.computeIfAbsent(rs.getString(1), key -> new ArrayList<>()).add(rs.getString(2));
                    });
        }
        Map<String, List<Double>> risks = new HashMap<>();
        Map<String, Long> resolved = new HashMap<>();
        if (!scored.isEmpty()) {
            Map<String, String> caseOf = new HashMap<>();
            scored.forEach(score -> caseOf.put(score.runId(), score.scenarioKey()));
            jdbc.query("""
                            select run_id, risk_score from run_decision
                             where run_id = any(:runs) and final_action is not null
                               and not coalesce(unresolved, false)""",
                    new MapSqlParameterSource("runs", caseOf.keySet().toArray(String[]::new)), rs -> {
                        String key = caseOf.get(rs.getString(1));
                        resolved.merge(key, 1L, Long::sum);
                        Object risk = rs.getObject(2);
                        if (risk instanceof Number number) {
                            risks.computeIfAbsent(key, k -> new ArrayList<>()).add(number.doubleValue());
                        }
                    });
        }
        List<BenchmarkView.CaseRow> rows = new ArrayList<>();
        byCase.forEach((key, runs) -> {
            Map<String, Map<String, Long>> results = new LinkedHashMap<>();
            Map<String, BenchmarkView.Cell> cells = new LinkedHashMap<>();
            Truth truth = runs.get(0).truth();
            for (String control : OutcomeSignature.CONTROLS) {
                Map<String, Long> counts = new TreeMap<>();
                long[] cell = new long[2];
                runs.forEach(run -> Optional.ofNullable(run.business().get(control)).ifPresent(result -> {
                    counts.merge(result.result().name(), 1L, Long::sum);
                    BusinessResult business = result.result();
                    if (business == BusinessResult.UNRESOLVED || business == BusinessResult.NOT_SCORED) {
                        return;
                    }
                    cell[1]++;
                    boolean right = truth.threat()
                            ? business == BusinessResult.STOPPED || business == BusinessResult.PARTLY_STOPPED
                            : business == BusinessResult.PASSED || business == BusinessResult.PASSED_AFTER_CHECK;
                    if (right) {
                        cell[0]++;
                    }
                }));
                results.put(control, counts);
                if (truth.threat() || truth.normal()) {
                    cells.put(control, new BenchmarkView.Cell(cell[0], cell[1]));
                }
            }
            Map<String, Long> actions = new TreeMap<>();
            Map<String, Long> verdicts = new TreeMap<>();
            Map<String, Long> sources = new TreeMap<>();
            runs.forEach(run -> run.verdicts().forEach(step -> {
                verdicts.merge(step.score().result().name(), 1L, Long::sum);
                sources.merge(step.source().name(), 1L, Long::sum);
                if (step.score().finalAction() != null
                        && step.score().result() != Scoring.VerdictResult.UNRESOLVED) {
                    actions.merge(step.score().finalAction(), 1L, Long::sum);
                }
            }));
            Map<String, String> title = catalog.find(key).map(ScenarioDefinition::title).orElse(Map.of());
            List<Double> caseRisks = risks.getOrDefault(key, List.of());
            BenchmarkView.RiskSpread risk = new BenchmarkView.RiskSpread(
                    caseRisks.stream().min(Double::compare).orElse(null),
                    caseRisks.stream().max(Double::compare).orElse(null), caseRisks.size(),
                    resolved.getOrDefault(key, 0L));
            rows.add(new BenchmarkView.CaseRow(key, runs.get(0).truth().classification(), title, runs.size(),
                    hashes.getOrDefault(key, List.of()), results, actions, verdicts, sources,
                    runs.stream().map(RunScore::runId).toList(), risk, cells));
        });
        return rows;
    }

    /**
     * Whether Contexa's business result is listed among its wrong runs (decision 6 of
     * docs/showcase/화면설계서-v2-구현계획.md): an attack it let through and a normal task it stopped. A run stopped
     * after some items left counts as stopped, with its exposed items shown under "decision and timing"; an
     * unresolved run is counted apart.
     */
    static boolean listedAsWrong(BusinessResult result) {
        return result == BusinessResult.MISSED || result == BusinessResult.HALTED;
    }

    /** The control scores of each named case group apart, in the groups' name order (work 13). */
    private List<BenchmarkView.Suite> suites(List<RunScore> scored) {
        Map<String, List<RunScore>> bySuite = new TreeMap<>();
        for (RunScore score : scored) {
            catalog.find(score.scenarioKey()).map(ScenarioDefinition::suite)
                    .ifPresent(suite -> bySuite.computeIfAbsent(suite, ignored -> new ArrayList<>()).add(score));
        }
        List<BenchmarkView.Suite> suites = new ArrayList<>();
        bySuite.forEach((suite, runs) -> suites.add(new BenchmarkView.Suite(suite,
                runs.stream().map(RunScore::scenarioKey).distinct().sorted().toList(), runs.size(), controls(runs))));
        return suites;
    }

    /** Contexa's attack runs the model judged risky, and how many of them were stopped (section 8 of the plan). */
    static BenchmarkView.RiskJudged riskJudged(List<RunScore> scored) {
        long runs = 0;
        long stopped = 0;
        for (RunScore score : scored) {
            if (JudgmentTiming.of(score).isEmpty() || !JudgmentTiming.judgedRisky(score)) {
                continue;
            }
            runs++;
            BusinessResult result = score.business().get("D").result();
            if (result == BusinessResult.STOPPED || result == BusinessResult.PARTLY_STOPPED) {
                stopped++;
            }
        }
        return new BenchmarkView.RiskJudged(runs, stopped);
    }

    /** Contexa's attack runs by how its answer came about, every kind present in its order (work 16). */
    static Map<String, Long> judgmentTiming(List<RunScore> scored) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (JudgmentTiming.Kind kind : JudgmentTiming.Kind.values()) {
            counts.put(kind.name(), 0L);
        }
        scored.forEach(score -> JudgmentTiming.of(score).ifPresent(kind -> counts.merge(kind.name(), 1L, Long::sum)));
        return counts;
    }

    /** Runs with a ground truth whose result for Contexa is unresolved (the engine made no real decision). */
    private static long unresolvedRuns(List<RunScore> scored) {
        return scored.stream().filter(score -> score.truth().threat() || score.truth().normal())
                .map(score -> score.business().get("D"))
                .filter(result -> result != null && result.result() == BusinessResult.UNRESOLVED).count();
    }

    /** Every wrong run of Contexa, newest first; the list is not cut, so its length is the count. */
    private List<BenchmarkView.WrongRun> wrongRuns(List<RunScore> scored) {
        List<RunScore> wrong = scored.stream().filter(score -> score.truth().threat() || score.truth().normal())
                .filter(score -> {
                    CaseScore result = score.business().get("D");
                    return result != null && listedAsWrong(result.result());
                }).toList();
        if (wrong.isEmpty()) {
            return List.of();
        }
        Map<String, Instant> started = new HashMap<>();
        jdbc.query("select run_id, started_at from run where run_id = any(:runs)",
                new MapSqlParameterSource("runs", wrong.stream().map(RunScore::runId).toArray(String[]::new)),
                rs -> {
                    started.put(rs.getString(1), instant(rs.getTimestamp(2)));
                });
        List<RunScore> newest = new ArrayList<>(wrong);
        newest.sort((left, right) -> started.getOrDefault(right.runId(), Instant.EPOCH)
                .compareTo(started.getOrDefault(left.runId(), Instant.EPOCH)));
        List<BenchmarkView.WrongRun> rows = new ArrayList<>();
        for (RunScore score : newest) {
            Integer step = score.verdicts().stream().filter(verdict -> verdict.score().finalAction() != null)
                    .map(verdict -> verdict.score().stepNo()).findFirst().orElse(null);
            List<Map<String, Object>> decision = step == null ? List.of() : jdbc.queryForList("""
                            select d.final_action, d.risk_score, d.reasoning,
                                   (select count(*) from run_decision_anatomy a,
                                           jsonb_array_elements(a.anatomy -> 'juxtaposition' -> 'coreAdverseLabels') x
                                     where a.request_id = d.request_id and (x ->> 'met')::boolean) as met,
                                   (select count(*) from run_decision_anatomy a
                                     where a.request_id = d.request_id
                                       and a.anatomy -> 'juxtaposition' -> 'coreAdverseLabels' is not null) as built
                              from run_decision d where d.run_id = :run and d.step_no = :step""",
                    new MapSqlParameterSource("run", score.runId()).addValue("step", step));
            Map<String, Object> row = decision.isEmpty() ? Map.of() : decision.get(0);
            CaseScore result = score.business().get("D");
            Number met = (Number) row.get("met");
            Number built = (Number) row.get("built");
            rows.add(new BenchmarkView.WrongRun(score.runId(), score.scenarioKey(), score.truth().classification(),
                    result.result().name(), result.exposedItems(), step, (String) row.get("final_action"),
                    row.get("risk_score") instanceof Number risk ? risk.doubleValue() : null,
                    (String) row.get("reasoning"),
                    built != null && built.longValue() > 0 && met != null ? met.intValue() : null,
                    started.get(score.runId())));
        }
        return rows;
    }

    private BenchmarkView.Engine engine(List<String> runIds, BenchmarkView.Spec spec) {
        if (runIds.isEmpty()) {
            return new BenchmarkView.Engine(0, Map.of(), 0, null, null, 0, null, priceSource, 0, 0, 0, null, 0, null,
                    0);
        }
        MapSqlParameterSource runs = new MapSqlParameterSource("runs", runIds.toArray(new String[0]));
        Map<String, Long> actions = new TreeMap<>();
        long[] counts = new long[2];
        jdbc.query("""
                        select d.final_action, coalesce(d.unresolved, false), count(*)
                          from run_decision d where d.run_id = any(:runs) and d.final_action is not null
                         group by d.final_action, coalesce(d.unresolved, false)""", runs, rs -> {
            if (rs.getBoolean(2)) {
                counts[1] += rs.getLong(3);
            } else {
                actions.merge(rs.getString(1), rs.getLong(3), Long::sum);
            }
            counts[0] += rs.getLong(3);
        });
        List<Long> times = jdbc.queryForList("""
                        select d.total_analysis_ms from run_decision d
                         where d.run_id = any(:runs) and d.final_action is not null and not coalesce(d.unresolved, false)
                           and d.total_analysis_ms is not null order by d.total_analysis_ms""", runs, Long.class);
        long[] tokens = new long[4];
        jdbc.query("""
                        select coalesce(sum(e.prompt_tokens), 0), coalesce(sum(e.completion_tokens), 0),
                               coalesce(sum((e.provider_response::jsonb #>> '{usage,prompt_tokens_details,cached_tokens}')
                                   ::bigint), 0), count(*)
                          from run_model_exchange e where e.run_id = any(:runs)""", runs, rs -> {
            tokens[0] = rs.getLong(1);
            tokens[1] = rs.getLong(2);
            tokens[2] = rs.getLong(3);
            tokens[3] = rs.getLong(4);
        });
        // What the engine recorded per decision: its tokens and its model calls (unresolved decisions included).
        Double[] means = new Double[2];
        long[] measured = new long[1];
        jdbc.query("""
                        select avg(d.total_tokens), count(d.total_tokens), avg(d.model_calls)
                          from run_decision d where d.run_id = any(:runs) and d.final_action is not null""", runs,
                rs -> {
                    means[0] = rs.getObject(1) == null ? null : rs.getDouble(1);
                    measured[0] = rs.getLong(2);
                    means[1] = rs.getObject(3) == null ? null : rs.getDouble(3);
                });
        Price price = prices.get(spec.chatModel());
        Double cost = price == null || counts[0] == 0 ? null
                : ((tokens[0] - tokens[2]) * price.input() + tokens[2] * price.cachedInput()
                + tokens[1] * price.output()) / 1_000_000 / counts[0];
        return new BenchmarkView.Engine(counts[0], actions, counts[1], percentile(times, 0.5), percentile(times, 0.95),
                times.size(), cost, priceSource, tokens[0], tokens[2], tokens[1], means[0], measured[0], means[1],
                tokens[3]);
    }

    private BenchmarkView.Observations observations(String settingHash) {
        MapSqlParameterSource spec = new MapSqlParameterSource("spec", settingHash);
        String sameSpec = settingHash == null ? "true" : "r.setting_hash = :spec";
        long live = count("select count(*) from run r where r.live_run and r.protocol_id is null and " + COUNTED
                + " and " + sameSpec, spec);
        long lab = count("select count(*) from lab_composition c join run r on r.run_id = c.run_id where " + COUNTED
                + " and " + sameSpec, spec);
        long composed = count("select count(*) from lab_composition c join run r on r.run_id = c.run_id where "
                + COUNTED + " and not c.designed and " + sameSpec, spec);
        long[] predictions = new long[4];
        jdbc.query("""
                        select p.call, r.scenario_definition #>> '{oracle,classification}'
                          from visitor_prediction p join run r on r.run_id = p.run_id
                         where %s and %s""".formatted(COUNTED, sameSpec), spec, rs -> {
            String call = rs.getString(1);
            String truth = rs.getString(2);
            predictions[3]++;
            if (!"THREAT".equals(truth) && !"NORMAL".equals(truth)) {
                return;
            }
            if ("UNSURE".equals(call)) {
                predictions[2]++;
                return;
            }
            predictions[1]++;
            if ("ATTACK".equals(call) == "THREAT".equals(truth)) {
                predictions[0]++;
            }
        });
        Map<String, Long> verdicts = new TreeMap<>();
        Map<String, Long> reasons = new TreeMap<>();
        Map<String, double[]> perVisitor = new HashMap<>();
        long[] total = new long[1];
        jdbc.query("""
                        select a.verdict, a.reasons::text, coalesce(a.visitor_hash, a.run_id || ':' || a.step_no)
                          from visitor_assessment a join run r on r.run_id = a.run_id
                         where a.assessed_at < :cutoff and %s and %s""".formatted(COUNTED, sameSpec),
                spec.addValue("cutoff", Timestamp.from(clock.instant().minus(Duration.ofHours(
                        ASSESSMENT_DELAY_HOURS)))), rs -> {
                    total[0]++;
                    verdicts.merge(rs.getString(1), 1L, Long::sum);
                    readList(rs.getString(2)).forEach(reason -> reasons.merge(reason, 1L, Long::sum));
                    double[] visitor = perVisitor.computeIfAbsent(rs.getString(3), key -> new double[2]);
                    if (!"UNSURE".equals(rs.getString(1))) {
                        visitor[1]++;
                        visitor[0] += "SOUND".equals(rs.getString(1)) ? 1 : 0;
                    }
                });
        List<double[]> voters = perVisitor.values().stream().filter(visitor -> visitor[1] > 0).toList();
        Double weighted = voters.isEmpty() ? null
                : voters.stream().mapToDouble(visitor -> visitor[0] / visitor[1]).average().orElse(0);
        return new BenchmarkView.Observations(live, lab, composed, predictions[3], rate(predictions[0], predictions[1]),
                predictions[2], total[0], perVisitor.size(), weighted, verdicts, reasons, ASSESSMENT_DELAY_HOURS);
    }

    static BenchmarkView.Rate rate(long hits, long total) {
        if (total == 0) {
            return new BenchmarkView.Rate(hits, total, null, null, null);
        }
        double z = 1.96;
        double p = (double) hits / total;
        double denominator = 1 + z * z / total;
        double centre = (p + z * z / (2.0 * total)) / denominator;
        double half = z * Math.sqrt(p * (1 - p) / total + z * z / (4.0 * total * total)) / denominator;
        return new BenchmarkView.Rate(hits, total, p, Math.max(0, centre - half), Math.min(1, centre + half));
    }

    static Double macro(Map<String, long[]> byCase) {
        List<Double> rates = byCase.values().stream().filter(cell -> cell[1] > 0)
                .map(cell -> (double) cell[0] / cell[1]).toList();
        return rates.isEmpty() ? null : rates.stream().mapToDouble(Double::doubleValue).average().orElse(0);
    }

    private static Long percentile(List<Long> sorted, double share) {
        if (sorted.isEmpty()) {
            return null;
        }
        return sorted.get(Math.min(sorted.size() - 1, (int) Math.round(share * (sorted.size() - 1))));
    }

    private long count(String sql, MapSqlParameterSource parameters) {
        Long value = jdbc.queryForObject(sql, parameters, Long.class);
        return value == null ? 0 : value;
    }

    private Map<String, Object> map(String text) {
        if (text == null) {
            return null;
        }
        try {
            return json.readValue(text, MAP);
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable model settings", e);
        }
    }

    private List<String> readList(String text) {
        try {
            return text == null ? List.of() : json.readValue(text, new TypeReference<List<String>>() {
            });
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable assessment reasons", e);
        }
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    static TreeSet<String> keys(Map<String, ?> map) {
        return new TreeSet<>(map.keySet());
    }
}
