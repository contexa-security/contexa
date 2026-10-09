package io.contexa.showcase.portal.journey;

import io.contexa.showcase.portal.anatomy.AnatomyStore;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy;
import io.contexa.showcase.portal.hook.HookStore;
import io.contexa.showcase.portal.journey.JourneyStore.VisitorRun;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The values of the card at the end of acts 1 to 3 (work 18 of docs/showcase/화면설계서-v2-구현계획.md): the server gives
 * the numbers and codes of the visitor's own run of the act's case and the dictionary holds the sentence. A visitor who
 * skipped the experience gets the same measurement's run instead, marked as such (D-37).
 */
public class ActEndCards {

    /** The case whose run each act's card states. */
    static final Map<Integer, String> ACT_CASES = Map.of(1, "A3", 2, "A3T", 3, "A6T");

    /**
     * @param source VISITOR_RUN, MEASUREMENT, or NONE when neither exists
     * @param values the card's numbers and codes as recorded
     */
    public record ActEnd(int act, String caseKey, String source, String runId, Map<String, Object> values) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final JourneyStore journeys;
    private final RunScores scores;
    private final ScenarioCatalog scenarios;
    private final AnatomyStore anatomies;
    private final HookStore hook;

    public ActEndCards(NamedParameterJdbcTemplate jdbc, JourneyStore journeys, RunScores scores,
                       ScenarioCatalog scenarios, AnatomyStore anatomies, HookStore hook) {
        this.jdbc = jdbc;
        this.journeys = journeys;
        this.scores = scores;
        this.scenarios = scenarios;
        this.anatomies = anatomies;
        this.hook = hook;
    }

    /** Empty for an act without a card. */
    public Optional<ActEnd> card(String visitor, int act) {
        String caseKey = ACT_CASES.get(act);
        if (caseKey == null) {
            return Optional.empty();
        }
        String runId = null;
        for (VisitorRun run : journeys.runs(visitor)) {
            if (run.scenarioKey().equals(caseKey) && !run.lab() && "COMPLETED".equals(run.status())) {
                runId = run.runId();
            }
        }
        String source = "VISITOR_RUN";
        if (runId == null) {
            runId = measuredRun(caseKey).orElse(null);
            source = "MEASUREMENT";
        }
        if (runId == null) {
            return Optional.of(new ActEnd(act, caseKey, "NONE", null, Map.of()));
        }
        Optional<RunScore> score = scores.score(runId);
        if (score.isEmpty()) {
            return Optional.of(new ActEnd(act, caseKey, "NONE", null, Map.of()));
        }
        return Optional.of(new ActEnd(act, caseKey, source, runId, act == 3 ? learning(runId)
                : outcome(caseKey, runId, score.get())));
    }

    /** Acts 1 and 2: what was asked, what Contexa decided and when, what left, and the number rule's result. */
    private Map<String, Object> outcome(String caseKey, String runId, RunScore score) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("requested", scenarios.find(caseKey).map(definition -> definition.steps().get(0).items())
                .orElse(null));
        List<Map<String, Object>> decision = jdbc.queryForList(
                "select final_action, total_analysis_ms from run_decision where run_id = :run and step_no = 1",
                new MapSqlParameterSource("run", runId));
        values.put("engineAction", decision.isEmpty() ? null : decision.get(0).get("final_action"));
        values.put("analysisMs", decision.isEmpty() ? null : decision.get(0).get("total_analysis_ms"));
        values.put("delivered", jdbc.queryForObject(
                "select coalesce(sum(delivered_items), 0) from run_arm_result where run_id = :run and control = 'D'",
                new MapSqlParameterSource("run", runId), Long.class));
        values.put("result", result(score, "D"));
        values.put("numberRule", result(score, "C1"));
        return values;
    }

    /** Act 3: the work profile observations the engine received at the first and the last request. */
    /**
     * Act 3's values: the engine's learned baseline at the start and at the end of the run (the last step's record holds
     * both), the same "usual behaviour" count try 3 and the learning-after screen show, so one word never names two
     * numbers on consecutive screens.
     */
    private Map<String, Object> learning(String runId) {
        Integer last = jdbc.queryForObject("select max(step_no) from run_decision where run_id = :run",
                new MapSqlParameterSource("run", runId), Integer.class);
        Map<String, Object> values = new LinkedHashMap<>();
        Optional<DecisionAnatomy.Figures> figures = last == null ? Optional.empty()
                : anatomies.anatomy(runId, last).map(DecisionAnatomy::figures);
        values.put("from", figures.map(DecisionAnatomy.Figures::baselineBefore).orElse(null));
        values.put("to", figures.map(DecisionAnatomy.Figures::baselineAfter).orElse(null));
        values.put("requests", last);
        return values;
    }

    /** The first completed, unforced run of the case in the measurement the first screen replays. */
    private Optional<String> measuredRun(String caseKey) {
        HookStore.Designated attacker = hook.designated().get(HookStore.Slot.ATTACKER);
        if (attacker == null) {
            return Optional.empty();
        }
        return hook.facts(attacker.runId()).flatMap(run -> hook.measurementRuns(run.protocolId(), caseKey).stream()
                .findFirst());
    }

    private static String result(RunScore score, String control) {
        CaseScore result = score.business().get(control);
        return result == null ? null : result.result().name();
    }
}
