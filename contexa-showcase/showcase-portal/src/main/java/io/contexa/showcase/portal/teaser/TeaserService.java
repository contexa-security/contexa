package io.contexa.showcase.portal.teaser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.anatomy.AnatomyStore;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy;
import io.contexa.showcase.portal.anatomy.WorkProfileSummary;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.hook.HookStore;
import io.contexa.showcase.portal.hook.HookStore.Designated;
import io.contexa.showcase.portal.hook.HookStore.RunFacts;
import io.contexa.showcase.portal.hook.HookStore.Slot;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The measured values of the teaser cards and the facts the screens' sentences rest on (work 19 and section 8 of
 * docs/showcase/화면설계서-v2-구현계획.md). The card's wording is the design's; each number here comes from a stored
 * record named as its source, and each sentence that states a fact carries whether the record makes it true, so a
 * screen shows the approved fallback sentence instead of a false one. Nothing is computed on the screen.
 */
public class TeaserService {

    /** The case definition fields that are not the case's conditions: its name, its answers and its grouping. */
    private static final Set<String> NOT_CONDITIONS = Set.of("key", "version", "title", "oracle", "frozenOn",
            "suite");
    /** A step's expected result per approach is an answer, not a condition. */
    private static final String STEP_ANSWERS = "expected";

    /**
     * @param kind CASE_DEFINITION, RUN, MEASUREMENT, TEMPLATE, BENCHMARK or CHALLENGES
     * @param ref  the case keys, run ID, protocol ID, template ID or setting hash
     */
    public record Source(String kind, String ref) {
    }

    /**
     * @param values the card's numbers and codes as recorded; empty when the source is missing
     * @param holds  whether the record makes the card's sentence true; null for a card that states no fact
     * @param missing why the values are empty (NO_HOOK, NO_TEMPLATE, NO_BENCHMARK, NO_RUN); null otherwise
     */
    public record Teaser(String key, Map<String, Object> values, Boolean holds, Source source, String missing) {
    }

    public record View(Instant computedAt, List<Teaser> teasers) {

        /** The cards whose sentence the record does not make true, so the screens show their fallback. */
        public List<String> falseConditions() {
            return teasers.stream().filter(teaser -> Boolean.FALSE.equals(teaser.holds())).map(Teaser::key).toList();
        }
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final HookStore hook;
    private final AnatomyStore anatomies;
    private final BenchmarkService benchmark;
    private final TemplateCurrency templates;
    private final ScenarioCatalog scenarios;
    private final ObjectMapper json;
    private final Clock clock;

    public TeaserService(NamedParameterJdbcTemplate jdbc, HookStore hook, AnatomyStore anatomies,
                         BenchmarkService benchmark, TemplateCurrency templates, ScenarioCatalog scenarios,
                         ObjectMapper json, Clock clock) {
        this.jdbc = jdbc;
        this.hook = hook;
        this.anatomies = anatomies;
        this.benchmark = benchmark;
        this.templates = templates;
        this.scenarios = scenarios;
        this.json = json;
        this.clock = clock;
    }

    public View view() throws IOException {
        Map<Slot, Designated> designated = hook.designated();
        Optional<RunFacts> attacker = Optional.ofNullable(designated.get(Slot.ATTACKER))
                .flatMap(run -> hook.facts(run.runId()));
        Optional<RunFacts> owner = Optional.ofNullable(designated.get(Slot.OWNER))
                .flatMap(run -> hook.facts(run.runId()));
        Optional<BenchmarkView> measured = benchmark.view(null).filter(view -> view.spec() != null);
        ScenarioDefinition attackerCase = scenarios.find(Slot.ATTACKER.caseKey()).orElseThrow();
        Optional<TemplateStore.ReadyTemplate> template = templates.current(attackerCase.protagonist());
        Optional<DecisionAnatomy> attackerAnatomy = attacker.flatMap(run -> anatomies.anatomy(run.runId(), 1));

        List<Teaser> teasers = new ArrayList<>();
        teasers.add(hookTry(attackerCase));
        teasers.add(attackerAnatomy.map(anatomy -> resultFacts(attacker.get(), anatomy))
                .orElse(missing("E1_RESULT_FACTS", "NO_HOOK")));
        teasers.add(attacker.map(this::reasonMailbox).orElse(missing("E1_REASON_MAILBOX", "NO_HOOK")));
        teasers.add(owner.map(this::afterRules).orElse(missing("E1_AFTER_RULES", "NO_HOOK")));
        teasers.add(caseDifference(attackerCase, scenarios.find(Slot.OWNER.caseKey()).orElseThrow()));
        teasers.add(owner.map(this::resume).orElse(missing("G_RULES_RESUME", "NO_HOOK")));
        teasers.add(template.map(this::learned).orElse(missing("FOLLOW_LEARNED", "NO_TEMPLATE")));
        teasers.add(template.map(this::taught).orElse(missing("LEARN_WHY_TAUGHT", "NO_TEMPLATE")));
        teasers.add(attackerAnatomy.map(anatomy -> lines(attacker.get(), anatomy))
                .orElse(missing("G_HOW_LINES", "NO_HOOK")));
        teasers.add(attacker.map(this::asyncDelivered).orElse(missing("E1_PROMPT_ASYNC", "NO_HOOK")));
        teasers.add(attacker.map(run -> observations(run.protocolId())).orElse(missing("SYNC_WHEN_OBSERVATIONS",
                "NO_HOOK")));
        teasers.add(measured.map(this::falseBlocks).orElse(missing("LEARN_AFTER_FALSE_BLOCKS", "NO_BENCHMARK")));
        teasers.add(measured.map(this::contextRuleStopped).orElse(missing("G_WHERE_C2", "NO_BENCHMARK")));
        teasers.add(measured.map(this::conclusions).orElse(missing("BENCHMARK_CONCLUSIONS", "NO_BENCHMARK")));
        teasers.add(measured.map(this::riskJudged).orElse(missing("RISK_JUDGED_STOPPED", "NO_BENCHMARK")));
        teasers.add(challengeOutcomes());
        return new View(clock.instant(), teasers);
    }

    /** Hook: "you take out {items} documents yourself"; the export size of the attacker's case. */
    private Teaser hookTry(ScenarioDefinition attackerCase) {
        return new Teaser("HOOK_TRY", Map.of("items", attackerCase.steps().get(0).items()), null,
                new Source("CASE_DEFINITION", attackerCase.key()), null);
    }

    /** Experience 1 result: "{n} facts were hit", the facts the engine received for the replayed attack. */
    private Teaser resultFacts(RunFacts run, DecisionAnatomy anatomy) {
        List<String> facts = new ArrayList<>();
        int departures = anatomy.juxtaposition().departures().size();
        if (departures > 0) {
            facts.add("BASELINE_DEPARTURE");
        }
        String sensitivity = anatomy.juxtaposition().sensitivity();
        if ("HIGH".equals(sensitivity) || "CRITICAL".equals(sensitivity)) {
            facts.add("HIGH_SENSITIVITY");
        }
        if (Boolean.TRUE.equals(anatomy.context().company().get("approvalMissing"))) {
            facts.add("APPROVAL_MISSING");
        }
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("count", facts.size());
        values.put("facts", facts);
        values.put("departures", departures);
        values.put("sensitivity", sensitivity);
        return new Teaser("E1_RESULT_FACTS", values, !facts.isEmpty(), new Source("RUN", run.runId()), null);
    }

    /** Experience 1 reason: "the code went to the real employee"; the replayed attack's check had no mailbox. */
    private Teaser reasonMailbox(RunFacts run) {
        List<String> reasons = jdbc.queryForList(
                "select coalesce(reason, case when answered then 'ANSWERED' end) from run_challenge"
                        + " where run_id = :run and step_no = 1", new MapSqlParameterSource("run", run.runId()),
                String.class);
        String reason = reasons.isEmpty() ? null : reasons.get(0);
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("reason", reason);
        return new Teaser("E1_REASON_MAILBOX", values, "NO_MAILBOX".equals(reason), new Source("RUN", run.runId()),
                null);
    }

    /** End of act 1: "the number rule stopped it"; the number rule over the measured runs of the real employee. */
    private Teaser afterRules(RunFacts run) {
        Map<String, Long> rules = new TreeMap<>();
        long[] counts = new long[2];
        jdbc.query("""
                        select a.outcome, a.rule_id from run r
                          join run_arm_result a on a.run_id = r.run_id and a.step_no = 1 and a.control = 'C1'
                         where r.protocol_id = :protocol and r.scenario_key = :case and r.status = 'COMPLETED'
                           and r.forced_action is null""",
                new MapSqlParameterSource("protocol", run.protocolId()).addValue("case", Slot.OWNER.caseKey()),
                rs -> {
                    counts[0]++;
                    if ("REFUSED".equals(rs.getString(1))) {
                        counts[1]++;
                        rules.merge(String.valueOf(rs.getString(2)), 1L, Long::sum);
                    }
                });
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("runs", counts[0]);
        values.put("refused", counts[1]);
        values.put("rules", rules);
        return new Teaser("E1_AFTER_RULES", values, counts[0] > 0 && counts[0] == counts[1],
                new Source("MEASUREMENT", run.protocolId()), null);
    }

    /** Experience 2 result: "what changed is one approval"; the conditions that differ between the two cases. */
    private Teaser caseDifference(ScenarioDefinition attackerCase, ScenarioDefinition ownerCase) {
        List<String> paths = new ArrayList<>();
        differences("", conditions(json.valueToTree(attackerCase)), conditions(json.valueToTree(ownerCase)), paths);
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("paths", paths);
        boolean onlyFacts = !paths.isEmpty() && paths.stream().allMatch(path -> path.startsWith("facts"));
        return new Teaser("E2_RESULT_DIFF", values, onlyFacts,
                new Source("CASE_DEFINITION", attackerCase.key() + "," + ownerCase.key()), null);
    }

    /** A case definition without the fields that are not its conditions. */
    static ObjectNode conditions(ObjectNode definition) {
        NOT_CONDITIONS.forEach(definition::remove);
        definition.path("steps").forEach(step -> {
            if (step instanceof ObjectNode node) {
                node.remove(STEP_ANSWERS);
            }
        });
        return definition;
    }

    static void differences(String path, JsonNode left, JsonNode right, List<String> paths) {
        if (left != null && right != null && left.isObject() && right.isObject()) {
            Set<String> names = new TreeSet<>();
            left.fieldNames().forEachRemaining(names::add);
            right.fieldNames().forEachRemaining(names::add);
            for (String name : names) {
                differences(path.isEmpty() ? name : path + "." + name, left.get(name), right.get(name), paths);
            }
            return;
        }
        if (left != null && right != null && left.isArray() && right.isArray() && left.size() == right.size()) {
            Iterator<JsonNode> a = left.elements();
            Iterator<JsonNode> b = right.elements();
            int index = 0;
            while (a.hasNext()) {
                differences(path + "[" + index++ + "]", a.next(), b.next(), paths);
            }
            return;
        }
        boolean leftMissing = left == null || left.isNull();
        boolean rightMissing = right == null || right.isNull();
        boolean same = leftMissing ? rightMissing : left.equals(right);
        if (!same) {
            paths.add(path);
        }
    }

    /** The rules: "back to work in {ms}"; the answered checks of the real employee's measured runs. */
    private Teaser resume(RunFacts run) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select c.run_id, c.reissue_elapsed_ms from run_challenge c join run r on r.run_id = c.run_id
                         where r.protocol_id = :protocol and r.scenario_key = :case and r.status = 'COMPLETED'
                           and r.forced_action is null and c.answered and c.reissue_elapsed_ms is not null
                         order by r.started_at""",
                new MapSqlParameterSource("protocol", run.protocolId()).addValue("case", Slot.OWNER.caseKey()));
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("reissueMs", rows.isEmpty() ? null : ((Number) rows.get(0).get("reissue_elapsed_ms")).longValue());
        values.put("runId", rows.isEmpty() ? null : rows.get(0).get("run_id"));
        values.put("answered", rows.size());
        return new Teaser("G_RULES_RESUME", values, !rows.isEmpty(), new Source("MEASUREMENT", run.protocolId()),
                null);
    }

    /** End of act 2: "{n} requests learned"; the template's baseline updates, with what was sent and allowed. */
    private Teaser learned(TemplateStore.ReadyTemplate template) {
        JsonNode baseline = baseline(template.snapshot());
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("learned", baseline.path("updateCount").asInt());
        values.putAll(stepCounts(template.templateId()));
        return new Teaser("FOLLOW_LEARNED", values, null, new Source("TEMPLATE", template.templateId()), null);
    }

    /** Learning 1: "reads {r} · downloads {d} · exports {e}"; the requests sent to teach the template. */
    private Teaser taught(TemplateStore.ReadyTemplate template) {
        return new Teaser("LEARN_WHY_TAUGHT", stepCounts(template.templateId()), null,
                new Source("TEMPLATE", template.templateId()), null);
    }

    private Map<String, Object> stepCounts(String templateId) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String key : List.of("sent", "allowed", "reads", "downloads", "exports")) {
            counts.put(key, 0L);
        }
        jdbc.query("select operation, final_action from template_step where template_id = :id",
                new MapSqlParameterSource("id", templateId), rs -> {
                    counts.merge("sent", 1L, Long::sum);
                    if ("ALLOW".equals(rs.getString(2))) {
                        counts.merge("allowed", 1L, Long::sum);
                    }
                    switch (rs.getString(1)) {
                        case "DOCUMENT_READ" -> counts.merge("reads", 1L, Long::sum);
                        case "DOCUMENT_DOWNLOAD" -> counts.merge("downloads", 1L, Long::sum);
                        case "EXPORT" -> counts.merge("exports", 1L, Long::sum);
                        default -> {
                        }
                    }
                });
        return new LinkedHashMap<>(counts);
    }

    /** How it judges: "{n} lines"; the content lines of the prompt sent for the replayed attack (D-38). */
    private Teaser lines(RunFacts run, DecisionAnatomy anatomy) {
        if (anatomy.promptLines() == null) {
            return new Teaser("G_HOW_LINES", Map.of(), null, new Source("RUN", run.runId()), "NO_TEXTS");
        }
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("lines", anatomy.promptLines().total());
        values.put("system", anatomy.promptLines().system());
        values.put("user", anatomy.promptLines().user());
        return new Teaser("G_HOW_LINES", values, null, new Source("RUN", run.runId()), null);
    }

    /**
     * The prompt: "{s} seconds to decide, and the records meanwhile? How {n} documents left": the replayed attack's
     * analysis time and the streamed export of the same measurement, decided after it.
     */
    private Teaser asyncDelivered(RunFacts attacker) {
        String protocolId = attacker.protocolId();
        List<Long> analysis = jdbc.queryForList(
                "select total_analysis_ms from run_decision where run_id = :run and step_no = 1",
                new MapSqlParameterSource("run", attacker.runId()), Long.class);
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select r.run_id, a.delivered_items from run r
                          join run_arm_result a on a.run_id = r.run_id and a.step_no = 1 and a.control = 'D'
                         where r.protocol_id = :protocol and r.scenario_key = 'A3S' and r.status = 'COMPLETED'
                           and r.forced_action is null order by r.started_at""",
                new MapSqlParameterSource("protocol", protocolId));
        List<Integer> delivered = rows.stream().map(row -> ((Number) row.get("delivered_items")).intValue()).toList();
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("delivered", delivered);
        values.put("runs", rows.size());
        values.put("analysisMs", analysis.isEmpty() ? null : analysis.get(0));
        values.put("analysisRunId", attacker.runId());
        return new Teaser("E1_PROMPT_ASYNC", values, !delivered.isEmpty() && delivered.stream().allMatch(n -> n > 0),
                new Source("MEASUREMENT", protocolId), null);
    }

    /**
     * Synchronous or not: "{from} → {to}"; the work profile observations the engine received at the first and the
     * last request of the same measurement's first normal five-lookup run.
     */
    private Teaser observations(String protocolId) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select r.run_id, max(d.step_no) as last_step from run r
                          join run_decision d on d.run_id = r.run_id
                         where r.protocol_id = :protocol and r.scenario_key = 'A6T' and r.status = 'COMPLETED'
                           and r.forced_action is null
                         group by r.run_id, r.started_at order by r.started_at limit 1""",
                new MapSqlParameterSource("protocol", protocolId));
        if (rows.isEmpty()) {
            return missing("SYNC_WHEN_OBSERVATIONS", "NO_RUN");
        }
        String runId = (String) rows.get(0).get("run_id");
        int last = ((Number) rows.get(0).get("last_step")).intValue();
        Integer from = anatomies.anatomy(runId, 1).map(WorkProfileSummary::observations).orElse(null);
        Integer to = anatomies.anatomy(runId, last).map(WorkProfileSummary::observations).orElse(null);
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("from", from);
        values.put("to", to);
        values.put("lastStep", last);
        return new Teaser("SYNC_WHEN_OBSERVATIONS", values, from != null && to != null && to > from,
                new Source("RUN", runId), null);
    }

    /** End of act 3: "normal work stopped {c1} times against {d}"; the number rule against Contexa. */
    private Teaser falseBlocks(BenchmarkView view) {
        BenchmarkView.ControlScore numberRule = control(view, "C1");
        BenchmarkView.ControlScore contexa = control(view, "D");
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("numberRule", numberRule == null ? null : numberRule.falseBlock().hits());
        values.put("contexa", contexa == null ? null : contexa.falseBlock().hits());
        values.put("normalRuns", contexa == null ? null : contexa.falseBlock().total());
        boolean holds = numberRule != null && contexa != null
                && numberRule.falseBlock().hits() > contexa.falseBlock().hits();
        return new Teaser("LEARN_AFTER_FALSE_BLOCKS", values, holds,
                new Source("BENCHMARK", view.spec().settingHash()), null);
    }

    /** Where it sits: "the work record rule stopped {n}"; attacks the context rule fully stopped. */
    private Teaser contextRuleStopped(BenchmarkView view) {
        BenchmarkView.ControlScore contextRule = control(view, "C2");
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("stopped", contextRule == null ? null : contextRule.stopped().hits());
        values.put("attackRuns", contextRule == null ? null : contextRule.stopped().total());
        return new Teaser("G_WHERE_C2", values, contextRule != null && contextRule.stopped().hits() > 0,
                new Source("BENCHMARK", view.spec().settingHash()), null);
    }

    /**
     * The benchmark's three questions, answered by the measurement: which approaches stopped the most attacks from
     * the start, which stopped the most normal work, and which reacted to attacks without stopping normal work.
     */
    private Teaser conclusions(BenchmarkView view) {
        long mostStopped = view.controls().stream().mapToLong(score -> score.stopped().hits()).max().orElse(0);
        long mostFalse = view.controls().stream().mapToLong(score -> score.falseBlock().hits()).max().orElse(0);
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("mostStopped", view.controls().stream()
                .filter(score -> score.stopped().hits() == mostStopped && mostStopped > 0)
                .map(BenchmarkView.ControlScore::control).toList());
        values.put("mostFalseBlocks", view.controls().stream()
                .filter(score -> score.falseBlock().hits() == mostFalse && mostFalse > 0)
                .map(BenchmarkView.ControlScore::control).toList());
        // Every approach that qualifies, most reactions first, with its count: the measurement may name more than one
        // (D-39), and the context rule's count carries the notice that it was written for the cases.
        Map<String, Long> reacted = new LinkedHashMap<>();
        view.controls().stream()
                .filter(score -> score.falseBlock().hits() == 0 && score.stoppedAny().hits() > 0)
                .sorted((left, right) -> Long.compare(right.stoppedAny().hits(), left.stoppedAny().hits()))
                .forEach(score -> reacted.put(score.control(), score.stoppedAny().hits()));
        values.put("reactedWithoutFalseBlocks", List.copyOf(reacted.keySet()));
        values.put("reactions", reacted);
        return new Teaser("BENCHMARK_CONCLUSIONS", values, null, new Source("BENCHMARK", view.spec().settingHash()),
                null);
    }

    /** "Every attack it judged risky was stopped": the measurement's risky judgements and how many were stopped. */
    private Teaser riskJudged(BenchmarkView view) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("judged", view.riskJudged().runs());
        values.put("stopped", view.riskJudged().stopped());
        values.put("judgedAllowMissed", view.judgmentTiming().get("JUDGED_ALLOW"));
        return new Teaser("RISK_JUDGED_STOPPED", values,
                view.riskJudged().runs() > 0 && view.riskJudged().runs() == view.riskJudged().stopped(),
                new Source("BENCHMARK", view.spec().settingHash()), null);
    }

    /**
     * What happened after the engine asked for the additional check, over every run that was not forced: answered and
     * resumed, no mailbox (an attacker), abandoned, expired, or the wrong code three times.
     */
    private Teaser challengeOutcomes() {
        Map<String, Long> outcomes = new TreeMap<>();
        jdbc.query("""
                        select coalesce(c.reason, case when c.answered then 'ANSWERED' else 'UNKNOWN' end), count(*)
                          from run_challenge c join run r on r.run_id = c.run_id
                         where r.forced_action is null group by 1""", new MapSqlParameterSource(),
                rs -> {
                    outcomes.put(rs.getString(1), rs.getLong(2));
                });
        Long resumed = jdbc.queryForObject("""
                        select count(*) from run_challenge c join run r on r.run_id = c.run_id
                         where r.forced_action is null and c.answered and c.reissue_outcome = 'DELIVERED'""",
                new MapSqlParameterSource(), Long.class);
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("outcomes", outcomes);
        values.put("total", outcomes.values().stream().mapToLong(Long::longValue).sum());
        // Answered and the original request went out again: the work resumed after the check.
        values.put("resumed", resumed == null ? 0 : resumed);
        return new Teaser("CHALLENGE_OUTCOMES", values, null, new Source("CHALLENGES", "forced_action is null"),
                null);
    }

    private static BenchmarkView.ControlScore control(BenchmarkView view, String control) {
        return view.controls().stream().filter(score -> score.control().equals(control)).findFirst().orElse(null);
    }

    private JsonNode baseline(JsonNode snapshot) {
        JsonNode baseline = snapshot.path("userBaseline");
        if (!baseline.isTextual()) {
            return baseline;
        }
        try {
            return json.readTree(baseline.asText());
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable template baseline", e);
        }
    }

    private static Teaser missing(String key, String why) {
        return new Teaser(key, Map.of(), null, null, why);
    }
}
