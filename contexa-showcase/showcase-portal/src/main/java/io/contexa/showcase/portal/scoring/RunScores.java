package io.contexa.showcase.portal.scoring;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.scoring.Scoring.StepAnswer;
import io.contexa.showcase.portal.scoring.Scoring.StepDecision;
import io.contexa.showcase.portal.scoring.Scoring.Truth;
import io.contexa.showcase.portal.scoring.Scoring.VerdictScore;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Scores stored runs with {@link Scoring} (docs/showcase/데모-재설계.md 5.0, W1-1). Everything is read from the run's
 * own records: the ground truth of the scenario definition the run executed (run.scenario_definition, V12), each
 * control's answer per step (run_arm_result), the additional check of control D (run_challenge) and control D's
 * decision per step (run_decision). A run recorded before the definition was kept with it is scored against the
 * catalog only when the catalog still holds the same scenario version; otherwise it has no ground truth and says so.
 */
public class RunScores {

    /** Where the ground truth of a run came from. */
    public enum TruthSource {
        /** The scenario definition stored with the run when it started. */
        RUN_SNAPSHOT,
        /** The catalog definition of the same scenario version (runs recorded before V12). */
        CATALOG_SAME_VERSION,
        /** Neither: the run is not scored. */
        NONE
    }

    /**
     * Where control D's answer to a step came from (review R-11): a model decision, a decision whose applied action
     * differs from the action proposed in the same record, a technical fallback, or no decision of this step at all (an
     * earlier decision refused it, the static authorization refused it, or it was not analysed).
     */
    public enum DecisionSource {
        MODEL, PROPOSAL_CHANGED, FALLBACK, PRIOR_DECISION, STATIC_AUTHORIZATION, NOT_ANALYSED
    }

    /**
     * @param decidedAt when the engine recorded its decision of the step (the source mark's recorded time, plan 1절 4);
     *                  null when the step has no decision record
     */
    public record StepVerdict(VerdictScore score, DecisionSource source, String proposedAction, Instant decidedAt) {

        /** A step verdict without a recorded time. */
        public StepVerdict(VerdictScore score, DecisionSource source, String proposedAction) {
            this(score, source, proposedAction, null);
        }
    }

    /**
     * The additional check control D asked for at a step, as recorded.
     *
     * @param releaseMillis from the check to the re-issued request; null when it was not answered
     */
    public record Check(int stepNo, boolean answered, String reissueOutcome, Long releaseMillis) {
    }

    /**
     * @param status        the run's status (a running run is scored on the steps sent so far)
     * @param definedSteps  steps of the executed definition; null without a definition
     * @param executedSteps the steps that were sent (a visitor may stop before the last step of a scenario)
     * @param business      the business result of each control over the steps sent, in control order
     * @param correct       {@link Scoring#correct} of each business result; a control without a value is neither
     *                      right nor wrong
     * @param title         the case's name by language: the one stored with the run (a lab case changed by the
     *                      visitor has its own), else the catalog's; null without either
     * @param finishedAt    when the run ended, as recorded; null while it runs
     */
    public record RunScore(String runId, String scenarioKey, int scenarioVersion, String status,
                           TruthSource truthSource, Truth truth, Integer definedSteps, int executedSteps,
                           Map<String, CaseScore> business, Map<String, Boolean> correct, List<StepVerdict> verdicts,
                           List<Check> checks, Map<String, String> title, Instant finishedAt) {

        /** A run score without a recorded end. */
        public RunScore(String runId, String scenarioKey, int scenarioVersion, String status, TruthSource truthSource,
                        Truth truth, Integer definedSteps, int executedSteps, Map<String, CaseScore> business,
                        Map<String, Boolean> correct, List<StepVerdict> verdicts, List<Check> checks,
                        Map<String, String> title) {
            this(runId, scenarioKey, scenarioVersion, status, truthSource, truth, definedSteps, executedSteps, business,
                    correct, verdicts, checks, title, null);
        }

        /** How many approaches got the case right (T-27: counted here, never on the screen). */
        @JsonProperty("rightControls")
        public long rightControls() {
            return correct.values().stream().filter(Boolean.TRUE::equals).count();
        }
    }

    static final List<String> CONTROLS = List.of("A", "B", "C1", "C2", "D");
    private static final List<String> PRIOR_DECISION_RULES = List.of("ACCOUNT_BLOCKED", "MFA_CHALLENGE_REQUIRED");

    private final NamedParameterJdbcTemplate jdbc;
    private final ScenarioCatalog scenarios;
    private final ObjectMapper json;

    public RunScores(NamedParameterJdbcTemplate jdbc, ScenarioCatalog scenarios, ObjectMapper json) {
        this.jdbc = jdbc;
        this.scenarios = scenarios;
        this.json = json;
    }

    record RunRow(String runId, String key, int version, String status, String definition, Instant finishedAt) {

        RunRow(String runId, String key, int version, String status, String definition) {
            this(runId, key, version, status, definition, null);
        }
    }

    record Arm(int stepNo, String control, String outcome, Integer httpStatus, long delivered, String ruleId) {
    }

    record Decision(int stepNo, String finalAction, String proposedAction, boolean unresolved, String applied,
                    Instant decidedAt) {

        Decision(int stepNo, String finalAction, String proposedAction, boolean unresolved, String applied) {
            this(stepNo, finalAction, proposedAction, unresolved, applied, null);
        }
    }

    /**
     * The ground truth of a run with the reason it is the truth, from the same source its score uses: the definition
     * stored with the run, else the catalog's definition of the same version, else none (F-13).
     *
     * @param rationale      why the truth is what it is, by language; null when the source has none
     * @param counterpoint   the expected objection to that truth, by language; null when the source has none
     * @param allowedActions the engine actions the truth counts as right; empty when the source has none
     */
    public record GroundTruth(TruthSource source, String classification, Map<String, String> rationale,
                              Map<String, String> counterpoint, List<String> allowedActions) {
    }

    public Optional<GroundTruth> groundTruth(String runId) {
        List<String[]> rows = jdbc.query("""
                        select scenario_key, scenario_version::text, scenario_definition::text
                          from run where run_id = :run""", new MapSqlParameterSource("run", runId),
                (rs, n) -> new String[] {rs.getString(1), rs.getString(2), rs.getString(3)});
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        String[] row = rows.get(0);
        Optional<JsonNode> snapshot = definition(row[2]);
        if (snapshot.isPresent() && !snapshot.get().path("oracle").isMissingNode()) {
            JsonNode oracle = snapshot.get().path("oracle");
            Truth truth = truth(oracle);
            return Optional.of(new GroundTruth(TruthSource.RUN_SNAPSHOT, truth.classification(),
                    byLanguage(oracle.path("rationale")), byLanguage(oracle.path("counterpoint")),
                    truth.allowedEngineActions()));
        }
        int version = Integer.parseInt(row[1]);
        return Optional.of(scenarios.find(row[0]).filter(scenario -> scenario.version() == version)
                .map(scenario -> new GroundTruth(TruthSource.CATALOG_SAME_VERSION,
                        scenario.oracle().classification(), scenario.oracle().rationale(),
                        scenario.oracle().counterpoint(), scenario.oracle().allowedEngineActions()))
                .orElse(new GroundTruth(TruthSource.NONE, null, null, null, List.of())));
    }

    private static Map<String, String> byLanguage(JsonNode text) {
        Map<String, String> values = new LinkedHashMap<>();
        text.fields().forEachRemaining(entry -> values.put(entry.getKey(), entry.getValue().asText()));
        return values.isEmpty() ? null : values;
    }

    public Optional<RunScore> score(String runId) {
        List<RunScore> scores = scoreAll(List.of(runId));
        return scores.isEmpty() ? Optional.empty() : Optional.of(scores.get(0));
    }

    /** Scores the given runs with four queries; unknown run IDs are left out. */
    public List<RunScore> scoreAll(Collection<String> runIds) {
        if (runIds.isEmpty()) {
            return List.of();
        }
        MapSqlParameterSource runs = new MapSqlParameterSource("runs", runIds.toArray(new String[0]));
        List<RunRow> rows = jdbc.query("""
                        select run_id, scenario_key, scenario_version, status, scenario_definition::text, finished_at
                          from run where run_id = any(:runs) order by started_at, run_id""", runs,
                (rs, n) -> new RunRow(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getString(4),
                        rs.getString(5), instant(rs.getTimestamp(6))));
        Map<String, List<Arm>> arms = new HashMap<>();
        jdbc.query("""
                        select run_id, step_no, control, outcome, http_status, delivered_items, rule_id
                          from run_arm_result where run_id = any(:runs) order by step_no, control""", runs,
                rs -> {
                    arms.computeIfAbsent(rs.getString(1), run -> new ArrayList<>()).add(new Arm(rs.getInt(2),
                            rs.getString(3), rs.getString(4), (Integer) rs.getObject(5), rs.getLong(6),
                            rs.getString(7)));
                });
        Map<String, Map<Integer, Check>> checks = new HashMap<>();
        jdbc.query("""
                        select run_id, step_no, answered, reissue_outcome, challenged_at, reissue_sent_at
                          from run_challenge where run_id = any(:runs)""", runs, rs -> {
            Timestamp challenged = rs.getTimestamp(5);
            Timestamp reissued = rs.getTimestamp(6);
            Long release = challenged == null || reissued == null ? null
                    : reissued.toInstant().toEpochMilli() - challenged.toInstant().toEpochMilli();
            checks.computeIfAbsent(rs.getString(1), run -> new TreeMap<>())
                    .put(rs.getInt(2), new Check(rs.getInt(2), rs.getBoolean(3), rs.getString(4), release));
        });
        Map<String, Map<Integer, Decision>> decisions = new HashMap<>();
        jdbc.query("""
                        select run_id, step_no, final_action, proposed_action, coalesce(unresolved, false), applied,
                               decided_at
                          from run_decision where run_id = any(:runs)""", runs, rs -> {
            decisions.computeIfAbsent(rs.getString(1), run -> new TreeMap<>()).put(rs.getInt(2),
                    new Decision(rs.getInt(2), rs.getString(3), rs.getString(4), rs.getBoolean(5),
                            rs.getString(6), instant(rs.getTimestamp(7))));
        });
        return rows.stream().map(row -> score(row, arms.getOrDefault(row.runId(), List.of()),
                checks.getOrDefault(row.runId(), Map.of()), decisions.getOrDefault(row.runId(), Map.of()))).toList();
    }

    RunScore score(RunRow row, List<Arm> arms, Map<Integer, Check> checks, Map<Integer, Decision> decisions) {
        TruthSource source;
        Truth truth;
        Integer definedSteps;
        Optional<JsonNode> snapshot = definition(row.definition());
        if (snapshot.isPresent() && !snapshot.get().path("oracle").isMissingNode()) {
            source = TruthSource.RUN_SNAPSHOT;
            truth = truth(snapshot.get().path("oracle"));
            definedSteps = snapshot.get().path("steps").isArray() ? snapshot.get().path("steps").size() : null;
        } else {
            Optional<ScenarioDefinition> catalog = scenarios.find(row.key())
                    .filter(scenario -> scenario.version() == row.version());
            source = catalog.isPresent() ? TruthSource.CATALOG_SAME_VERSION : TruthSource.NONE;
            truth = catalog.map(scenario -> new Truth(scenario.oracle().classification(),
                    scenario.oracle().allowedEngineActions())).orElse(new Truth(null, List.of()));
            definedSteps = catalog.map(scenario -> scenario.steps().size()).orElse(null);
        }
        Map<String, List<StepAnswer>> answers = new LinkedHashMap<>();
        CONTROLS.forEach(control -> answers.put(control, new ArrayList<>()));
        Map<Integer, Arm> controlD = new TreeMap<>();
        int executed = 0;
        for (Arm arm : arms) {
            executed = Math.max(executed, arm.stepNo());
            Boolean checkPassed = null;
            if ("D".equals(arm.control())) {
                controlD.put(arm.stepNo(), arm);
                Check check = checks.get(arm.stepNo());
                if (check != null) {
                    checkPassed = check.answered() && "DELIVERED".equals(check.reissueOutcome());
                }
            }
            answers.computeIfAbsent(arm.control(), control -> new ArrayList<>()).add(new StepAnswer(arm.stepNo(),
                    arm.outcome(), arm.httpStatus(), arm.delivered(), checkPassed));
        }
        Map<String, CaseScore> business = new LinkedHashMap<>();
        Map<String, Boolean> correct = new LinkedHashMap<>();
        answers.forEach((control, list) -> {
            CaseScore caseScore = Scoring.business(truth, list);
            business.put(control, caseScore);
            Boolean right = Scoring.correct(caseScore.result());
            if (right != null) {
                correct.put(control, right);
            }
        });
        List<StepVerdict> verdicts = new ArrayList<>();
        for (Map.Entry<Integer, Arm> entry : controlD.entrySet()) {
            Decision decision = decisions.get(entry.getKey());
            StepDecision stepDecision = decision == null
                    ? new StepDecision(entry.getKey(), null, false, "NONE")
                    : new StepDecision(entry.getKey(), decision.finalAction(), decision.unresolved(),
                    decision.applied());
            verdicts.add(new StepVerdict(Scoring.verdict(truth, stepDecision, executed),
                    source(decision, entry.getValue()), decision == null ? null : decision.proposedAction(),
                    decision == null ? null : decision.decidedAt()));
        }
        Map<String, String> title = snapshot.map(node -> byLanguage(node.path("title")))
                .or(() -> scenarios.find(row.key()).map(ScenarioDefinition::title)).orElse(null);
        return new RunScore(row.runId(), row.key(), row.version(), row.status(), source, truth, definedSteps,
                executed, business, correct, verdicts, List.copyOf(checks.values()), title, row.finishedAt());
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    static DecisionSource source(Decision decision, Arm arm) {
        if (decision != null && decision.finalAction() != null) {
            if (decision.unresolved()) {
                return DecisionSource.FALLBACK;
            }
            boolean changed = decision.proposedAction() != null
                    && !decision.proposedAction().equals(decision.finalAction());
            return changed ? DecisionSource.PROPOSAL_CHANGED : DecisionSource.MODEL;
        }
        if (arm.ruleId() != null && PRIOR_DECISION_RULES.contains(arm.ruleId())) {
            return DecisionSource.PRIOR_DECISION;
        }
        return "REFUSED".equals(arm.outcome()) ? DecisionSource.STATIC_AUTHORIZATION : DecisionSource.NOT_ANALYSED;
    }

    private static Truth truth(JsonNode oracle) {
        List<String> allowed = new ArrayList<>();
        oracle.path("allowedEngineActions").forEach(action -> allowed.add(action.asText()));
        String classification = oracle.path("classification").isTextual()
                ? oracle.path("classification").asText() : null;
        return new Truth(classification, allowed);
    }

    private Optional<JsonNode> definition(String text) {
        if (text == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(json.readTree(text));
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable stored scenario definition", e);
        }
    }
}
