package io.contexa.showcase.portal.benchmark;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * docs/agent Agent중심-화면 AS-11: the agent part of the benchmark, counted from the operator's recorded agent runs by the
 * one scoring rule of an agent task (its proof: where each control first stopped the work). Only runs of the
 * definitions in force are counted, so a case changed after its measurement counts as "not measured" until it is run
 * again. A visitor's live run, a forced run and a run that did not finish are not measurements. Only runs of the current
 * build are counted (DEC-86 of docs/showcase/UX-R1-구현계획서.md): the build of the measurement setting the benchmark
 * shows by default, so the agent part and the person part speak of the same engine.
 */
public class AgentBenchmarkService {

    /**
     * A case of the catalog, the hash of its definition in force and its truth (NORMAL, THREAT, UNCERTAIN; null when not
     * told). A case whose truth is UNCERTAIN is counted as neither an attack nor a normal case.
     */
    public record CatalogCase(String key, String sha256, String classification) {

        public CatalogCase(String key, String sha256) {
            this(key, sha256, null);
        }
    }

    /**
     * What the runs of one path (or all) show.
     *
     * @param attacks        runs of attack cases
     * @param existingMissed attack runs that none of the four existing controls (A, B, C1, C2) stopped
     * @param contexaStopped of those, the runs Contexa (control D) stopped
     * @param normals        runs of normal cases
     * @param falseBlocks    normal runs Contexa stopped
     * @param contexaShare   the share of the missed attack runs Contexa stopped (0 to 1); null when none were missed
     */
    public record PathRow(String path, int runs, int attacks, int existingMissed, int contexaStopped, int normals,
                          int falseBlocks, Double contexaShare) {
    }

    /**
     * @param cells     a case on a path run at least twice
     * @param differing the cells whose runs did not all end alike at control D (stopped at some step, or not)
     */
    public record Variation(int cells, int differing) {
    }

    public record Scope(int runs, int cases, Instant from, Instant to) {
    }

    /**
     * The build the counted runs were measured on: the fields of the current measurement setting's specification that
     * make the engine (its model settings are matched too). The setting hash also holds the template version, which an
     * agent case and a person case need not share, so runs are matched on these fields, not on the hash.
     *
     * @param settingHash the measurement setting the build is read from
     */
    public record Build(String settingHash, String codeCommit, String engineVersion, String effectiveMode,
                       String promptBundle) {
    }

    /**
     * @param notMeasured  the catalog cases with no run of their definition in force on the current build
     * @param contexaMissed the cases with an attack run that no control stopped, Contexa included
     * @param uncertain    the cases whose truth is UNCERTAIN: measured, but in neither the attack nor the normal count
     * @param build        the build the runs were counted for; null without a measurement setting, and then no run counts
     */
    public record View(Scope scope, List<PathRow> byPath, PathRow total, Variation variation, List<String> notMeasured,
                       List<String> contexaMissed, List<String> uncertain, Build build) {
    }

    private record CurrentBuild(Build build, String modelSettings) {
    }

    private static final List<String> EXISTING = List.of("A", "B", "C1", "C2");

    /**
     * The business agent models whose runs are no part of the benchmark: the agent the benchmark measures is the company's,
     * and a run with the agent on Claude Sonnet 5.5 is one of the model comparison (docs/agent 모델비교, 2026-10-27).
     */
    static final List<String> COMPARISON_AGENT_MODELS = List.of("claude-sonnet-5-5");

    private final NamedParameterJdbcTemplate jdbc;
    private final Supplier<Optional<String>> currentSetting;

    /** @param currentSetting the measurement setting the benchmark shows by default */
    public AgentBenchmarkService(NamedParameterJdbcTemplate jdbc, Supplier<Optional<String>> currentSetting) {
        this.jdbc = jdbc;
        this.currentSetting = currentSetting;
    }

    public View view(List<CatalogCase> catalog) {
        Optional<CurrentBuild> current = currentSetting.get().flatMap(this::buildOf);
        Map<String, String> inForce = new LinkedHashMap<>();
        Set<String> uncertain = new LinkedHashSet<>();
        catalog.forEach(found -> {
            inForce.put(found.key(), found.sha256());
            if ("UNCERTAIN".equals(found.classification())) {
                uncertain.add(found.key());
            }
        });
        List<Map<String, Object>> rows = inForce.isEmpty() || current.isEmpty() ? List.of() : jdbc.queryForList("""
                        select r.run_id, r.scenario_key, r.scenario_sha256, r.started_at, t.sender,
                               (t.proof->>'attack')::boolean as attack,
                               t.proof->'controls'->'A'->>'firstStopStep' as a,
                               t.proof->'controls'->'B'->>'firstStopStep' as b,
                               t.proof->'controls'->'C1'->>'firstStopStep' as c1,
                               t.proof->'controls'->'C2'->>'firstStopStep' as c2,
                               t.proof->'controls'->'D'->>'firstStopStep' as d
                          from run r join run_agent_task t on t.run_id = r.run_id
                          join execution_spec s on s.spec_hash = r.spec_hash
                         where r.status = 'COMPLETED' and r.forced_action is null and r.live_visitor_hash is null
                           and r.scenario_key in (:keys) and t.proof is not null
                           and t.model not in (:comparison)
                           and s.code_commit = :commit and s.engine_version = :engine and s.effective_mode = :mode
                           and s.prompt_bundle is not distinct from :bundle
                           and s.model_settings is not distinct from cast(:settings as jsonb)
                         order by r.started_at""", new MapSqlParameterSource("keys", inForce.keySet())
                .addValue("comparison", COMPARISON_AGENT_MODELS)
                .addValue("commit", current.get().build().codeCommit())
                .addValue("engine", current.get().build().engineVersion())
                .addValue("mode", current.get().build().effectiveMode())
                .addValue("bundle", current.get().build().promptBundle(), Types.VARCHAR)
                .addValue("settings", current.get().modelSettings(), Types.VARCHAR));
        Map<String, int[]> byPath = new TreeMap<>();
        int[] total = new int[6];
        Map<String, Set<Boolean>> outcomes = new LinkedHashMap<>();
        Map<String, Integer> perCell = new LinkedHashMap<>();
        Set<String> cases = new LinkedHashSet<>();
        Set<String> missedByAll = new LinkedHashSet<>();
        Instant from = null;
        Instant to = null;
        int runs = 0;
        for (Map<String, Object> row : rows) {
            String key = (String) row.get("scenario_key");
            if (!Objects.equals(inForce.get(key), row.get("scenario_sha256")) || uncertain.contains(key)) {
                continue;
            }
            runs++;
            cases.add(key);
            Instant at = instant(row.get("started_at"));
            from = from == null || at.isBefore(from) ? at : from;
            to = to == null || at.isAfter(to) ? at : to;
            String path = (String) row.get("sender");
            boolean attack = Boolean.TRUE.equals(row.get("attack"));
            boolean contexaStopped = row.get("d") != null;
            boolean existingStopped = EXISTING.stream().anyMatch(control -> row.get(control.toLowerCase()) != null);
            int[] counts = byPath.computeIfAbsent(path, ignored -> new int[6]);
            for (int[] target : new int[][]{counts, total}) {
                target[0]++;
                if (attack) {
                    target[1]++;
                    if (!existingStopped && !contexaStopped && target == counts) {
                        missedByAll.add(key);
                    }
                    if (!existingStopped) {
                        target[2]++;
                        if (contexaStopped) {
                            target[3]++;
                        }
                    }
                } else {
                    target[4]++;
                    if (contexaStopped) {
                        target[5]++;
                    }
                }
            }
            String cell = key + "|" + path;
            perCell.merge(cell, 1, Integer::sum);
            outcomes.computeIfAbsent(cell, ignored -> new LinkedHashSet<>()).add(contexaStopped);
        }
        int cells = (int) perCell.values().stream().filter(count -> count >= 2).count();
        int differing = (int) perCell.entrySet().stream()
                .filter(entry -> entry.getValue() >= 2 && outcomes.get(entry.getKey()).size() > 1).count();
        List<String> notMeasured = new ArrayList<>();
        for (CatalogCase found : catalog) {
            if (!cases.contains(found.key()) && !uncertain.contains(found.key())) {
                notMeasured.add(found.key());
            }
        }
        List<PathRow> paths = new ArrayList<>();
        byPath.forEach((path, counts) -> paths.add(row(path, counts)));
        return new View(new Scope(runs, cases.size(), from, to), paths, row("ALL", total), new Variation(cells, differing),
                notMeasured, new ArrayList<>(missedByAll), new ArrayList<>(uncertain),
                current.map(CurrentBuild::build).orElse(null));
    }

    /** The build fields of a measurement setting, read from the specification of its latest counted protocol run. */
    private Optional<CurrentBuild> buildOf(String settingHash) {
        return jdbc.query("""
                        select s.code_commit, s.engine_version, s.effective_mode, s.prompt_bundle, s.model_settings::text
                          from run r join execution_spec s on s.spec_hash = r.spec_hash
                         where r.setting_hash = :setting and r.protocol_id is not null and r.status = 'COMPLETED'
                           and r.forced_action is null
                         order by r.started_at desc limit 1""", new MapSqlParameterSource("setting", settingHash),
                (rs, n) -> new CurrentBuild(new Build(settingHash, rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4)), rs.getString(5))).stream().findFirst();
    }

    private static PathRow row(String path, int[] counts) {
        return new PathRow(path, counts[0], counts[1], counts[2], counts[3], counts[4], counts[5],
                counts[2] == 0 ? null : (double) counts[3] / counts[2]);
    }

    private static Instant instant(Object value) {
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant();
        }
        if (value instanceof OffsetDateTime time) {
            return time.toInstant();
        }
        return (Instant) value;
    }
}
