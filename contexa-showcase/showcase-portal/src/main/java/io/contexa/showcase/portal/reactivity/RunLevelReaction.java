package io.contexa.showcase.portal.reactivity;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * U6-4 (the prompt trust screen reinforcement in docs/showcase, line 160): the plan's A1 and A2 counted by run, by
 * the definition the measurement gates use (prompt-audit/p0/run_level_reaction.py, the P8 preregistration's A1 and
 * A2). The population is a measurement's runs without a forced action; a run reacted when any step's final action is
 * CHALLENGE, ESCALATE or BLOCK; a run no step of which the engine decided (no final action, not unresolved, no model
 * call: a role check that stopped it before the engine) is neither a reaction nor a miss and is left out; an
 * unresolved or failed decision stays in as a miss. The class is the case definition's oracle.classification: A1
 * counts THREAT runs, A2 NORMAL runs (an UNCERTAIN run is in neither). The benchmark's RiskJudged counts something
 * else (attack runs a model decision judged risky) and is not this.
 */
public final class RunLevelReaction {

    static final String THREAT = "THREAT";
    static final String NORMAL = "NORMAL";
    /** The final actions a run reacted with. */
    private static final Set<String> REACTED = Set.of("CHALLENGE", "ESCALATE", "BLOCK");

    /** One decision step of a measurement's run. */
    public record Step(String runId, String caseKey, String finalAction, boolean unresolved, int modelCalls) {
    }

    /**
     * The counts of one measurement.
     *
     * @param attackRuns        THREAT runs that reached the engine (A1's denominator)
     * @param attackReacted     of them, the runs that reacted (A1)
     * @param normalRuns        NORMAL runs that reached the engine (A2's denominator)
     * @param normalReacted     of them, the runs asked to verify or more (A2)
     * @param notReachingEngine classified runs no step of which the engine decided, left out
     * @param unclassified      runs of a case no definition classifies, left out
     */
    public record Counts(long attackRuns, long attackReacted, long normalRuns, long normalReacted,
                         long notReachingEngine, long unclassified) {
    }

    private RunLevelReaction() {
    }

    /** A1 and A2 of a measurement's steps; classOf gives a case key's classification, null when none. */
    public static Counts count(List<Step> steps, Function<String, String> classOf) {
        Map<String, String> caseOf = new LinkedHashMap<>();
        Map<String, Boolean> reacted = new HashMap<>();
        Map<String, Boolean> engine = new HashMap<>();
        for (Step step : steps) {
            caseOf.putIfAbsent(step.runId(), step.caseKey());
            reacted.merge(step.runId(), step.finalAction() != null && REACTED.contains(step.finalAction()),
                    Boolean::logicalOr);
            engine.merge(step.runId(), step.finalAction() != null || step.unresolved() || step.modelCalls() > 0,
                    Boolean::logicalOr);
        }
        long attackRuns = 0;
        long attackReacted = 0;
        long normalRuns = 0;
        long normalReacted = 0;
        long notReachingEngine = 0;
        long unclassified = 0;
        for (Map.Entry<String, String> run : caseOf.entrySet()) {
            String kind = run.getValue() == null ? null : classOf.apply(run.getValue());
            if (kind == null) {
                unclassified++;
            } else if (!engine.get(run.getKey())) {
                notReachingEngine++;
            } else if (THREAT.equals(kind)) {
                attackRuns++;
                attackReacted += reacted.get(run.getKey()) ? 1 : 0;
            } else if (NORMAL.equals(kind)) {
                normalRuns++;
                normalReacted += reacted.get(run.getKey()) ? 1 : 0;
            }
        }
        return new Counts(attackRuns, attackReacted, normalRuns, normalReacted, notReachingEngine, unclassified);
    }

    /** The decision steps of a measurement's runs without a forced action. */
    public static List<Step> steps(NamedParameterJdbcTemplate jdbc, String protocol) {
        return jdbc.query("""
                        select r.run_id, r.scenario_key, d.final_action, coalesce(d.unresolved, false),
                               coalesce(d.model_calls, 0)
                          from run r join run_decision d on d.run_id = r.run_id
                         where r.protocol_id = :protocol and r.forced_action is null
                         order by r.run_id, d.step_no""",
                new MapSqlParameterSource("protocol", protocol),
                (rs, n) -> new Step(rs.getString(1), rs.getString(2), rs.getString(3), rs.getBoolean(4), rs.getInt(5)));
    }

    /** The prompt bundle a measurement's runs ran (execution_spec.prompt_bundle); null when none or more than one. */
    public static String bundle(NamedParameterJdbcTemplate jdbc, String protocol) {
        List<String> bundles = jdbc.queryForList("""
                        select distinct s.prompt_bundle
                          from run r join execution_spec s on s.spec_hash = r.spec_hash
                         where r.protocol_id = :protocol and s.prompt_bundle is not null""",
                new MapSqlParameterSource("protocol", protocol), String.class);
        return bundles.size() == 1 ? bundles.get(0) : null;
    }
}
