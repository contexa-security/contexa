package io.contexa.showcase.portal.rules;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * The rules scene with a visitor's settings (docs/showcase/데모-재설계.md H-10): the rule classes of the plain workload
 * decide the recorded requests of the scene's cases again, from the facts each control recorded. The screen computes
 * nothing of its own; a request the role check refused keeps its recorded refusal, since no rule setting reaches it.
 */
public class RuleEvaluation {

    /** Most distinct settings whose result is kept; the same settings within a case refresh are answered again. */
    static final int KEPT = 64;
    static final int MAX_ITEMS = 1_000_000;
    static final String ROLE_CHECK = "RBAC";
    static final String THREAT = "THREAT";
    static final String NORMAL = "NORMAL";
    static final String DELIVERED = "DELIVERED";
    static final String HELD = "HELD";
    static final Set<String> BLOCKING = Set.of("STOPPED", "CUT", "BROKEN");

    /**
     * A visitor's settings as the scene holds them; null for the assigned limit keeps the company's policy row.
     */
    public record Settings(int nightStartHour, int nightEndHour, int volumeLimit, boolean dormant, boolean external,
                           boolean falseClaim, boolean approval, boolean ticket, boolean assigned,
                           Integer assignedLimit, boolean history) {

        boolean valid() {
            return nightStartHour >= 0 && nightStartHour <= 23 && nightEndHour >= 0 && nightEndHour <= 23
                    && volumeLimit >= 0 && volumeLimit <= MAX_ITEMS
                    && (assignedLimit == null || assignedLimit >= 0 && assignedLimit <= MAX_ITEMS);
        }

        Map<String, Object> forRules() {
            Map<String, Object> rules = new LinkedHashMap<>();
            rules.put("nightStart", String.format("%02d:00", nightStartHour));
            rules.put("nightEnd", String.format("%02d:00", nightEndHour));
            rules.put("volumeLimit", volumeLimit);
            rules.put("dormant", dormant);
            rules.put("external", external);
            rules.put("falseClaim", falseClaim);
            rules.put("approval", approval);
            rules.put("ticket", ticket);
            rules.put("assigned", assigned);
            rules.put("assignedLimit", assignedLimit);
            rules.put("history", history);
            return rules;
        }
    }

    /**
     * The values the rule controls run with, as the plain workload publishes them (/internal/rules), in the scene's
     * terms; every switch is on.
     */
    public record Defaults(int nightStartHour, int nightEndHour, int volumeLimit, int assignedLimit,
                           int dormantWindowDays, int historyWindowDays, String ruleVersion) {

        /** The settings the rule controls run with: the published hours and limit, every switch on. */
        @JsonProperty("settings")
        public Settings settings() {
            return new Settings(nightStartHour, nightEndHour, volumeLimit, true, true, true, true, true, true, null,
                    true);
        }
    }

    /**
     * One control's decision of a request; {@code asRecorded} marks the role check's refusal kept from the run, and
     * {@code notRecorded} names a fact the run did not record, so the request is not decided again.
     */
    public record Decision(String ruleId, Boolean allowed, String notRecorded, boolean asRecorded) {
    }

    public record StepResult(int stepNo, Decision c1, Decision c2) {
    }

    /**
     * @param stopped   whether a rule control refused one of the case's requests; null when that cannot be said
     * @param c1Stopped the same for the threshold rule alone
     * @param c2Stopped the same for the business record rule alone
     */
    public record CaseResult(String scenario, String classification, Boolean stopped, Boolean c1Stopped,
                             Boolean c2Stopped, List<StepResult> steps) {
    }

    /**
     * How one approach handled the cases with a ground truth, counted here so the screen counts nothing. For Contexa
     * the counts are its recorded outcomes on the same cases: an attack is stopped when any request did not deliver; a
     * normal task is blocked when a request was stopped, cut or broken, and checked when it was only held for the
     * identity check (the benchmark's friction, not a block).
     *
     * @param undecided cases whose result cannot be said (a fact the run did not record)
     */
    public record Tally(int attacks, int attacksStopped, int normals, int normalsBlocked, int normalsChecked,
                        int undecided) {
    }

    /** A case whose result for one rule control differs from the result under the published settings. */
    public record Change(String scenario, String classification, String control, Boolean before, Boolean now) {
    }

    /**
     * @param tallies per approach (C1, C2 under these settings; D as recorded)
     * @param changed the cases whose result moved from the published settings', per rule control
     */
    public record Result(Instant casesComputedAt, Settings settings, List<CaseResult> cases,
                         Map<String, Tally> tallies, List<Change> changed) {
    }

    private final RuleCases cases;
    private final WorkloadAdmin admin;
    private final ObjectMapper json;
    private final Clock clock;
    private final Map<String, Result> kept = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Result> eldest) {
            return size() > KEPT;
        }
    };
    private Defaults defaults;
    private Instant defaultsAt;

    public RuleEvaluation(RuleCases cases, WorkloadAdmin admin, ObjectMapper json, Clock clock) {
        this.cases = cases;
        this.admin = admin;
        this.json = json;
        this.clock = clock;
    }

    /** The published values, read again at most every minute. */
    public synchronized Defaults defaults() throws IOException {
        Instant now = clock.instant();
        if (defaults == null || !now.isBefore(defaultsAt.plus(RuleCases.CACHE))) {
            JsonNode rules = admin.rules();
            JsonNode c1 = rules.path("c1");
            JsonNode c2 = rules.path("c2");
            defaults = new Defaults(hour(c1.path("nightStart").asText()), hour(c1.path("nightEnd").asText()),
                    c1.path("volumeLimit").asInt(), c2.path("exportApprovalPolicy").path("assignedExportLimit").asInt(),
                    c1.path("dormantWindowDays").asInt(), c2.path("historyWindowDays").asInt(),
                    rules.path("sha256").asText());
            defaultsAt = now;
        }
        return defaults;
    }

    private static int hour(String time) {
        return Integer.parseInt(time.substring(0, 2));
    }

    public synchronized Result evaluate(Settings settings) throws IOException {
        RuleCases.View view = cases.view();
        String key = view.computedAt() + " " + settings;
        Result known = kept.get(key);
        if (known != null) {
            return known;
        }
        List<CaseResult> results = decide(view, settings);
        Settings published = defaults().settings();
        List<CaseResult> before = published.equals(settings) ? results : decide(view, published);
        Result result = new Result(view.computedAt(), settings, results, tallies(view.cases(), results),
                changes(before, results));
        kept.put(key, result);
        return result;
    }

    private List<CaseResult> decide(RuleCases.View view, Settings settings) throws IOException {
        List<Map<String, Object>> steps = new ArrayList<>();
        for (RuleCases.Case ruleCase : view.cases()) {
            for (RuleCases.CaseStep step : ruleCase.steps()) {
                if (!refusedByRole(step)) {
                    Map<String, Object> request = new LinkedHashMap<>();
                    request.put("operation", step.operation());
                    request.put("username", null);
                    request.put("companyTime", step.companyTime());
                    request.put("c1Facts", json.writeValueAsString(step.c1Facts()));
                    request.put("c2Facts", json.writeValueAsString(step.c2Facts()));
                    steps.add(request);
                }
            }
        }
        JsonNode decided = steps.isEmpty() ? json.createArrayNode()
                : admin.evaluateRules(Map.of("settings", settings.forRules(), "steps", steps));
        if (!decided.isArray() || decided.size() != steps.size()) {
            throw new IOException("Rule evaluation answered " + decided.size() + " of " + steps.size() + " requests");
        }
        int next = 0;
        List<CaseResult> results = new ArrayList<>();
        for (RuleCases.Case ruleCase : view.cases()) {
            List<StepResult> stepResults = new ArrayList<>();
            for (RuleCases.CaseStep step : ruleCase.steps()) {
                if (refusedByRole(step)) {
                    Decision refused = new Decision(ROLE_CHECK, false, null, true);
                    stepResults.add(new StepResult(step.stepNo(), refused, refused));
                } else {
                    JsonNode result = decided.get(next++);
                    stepResults.add(new StepResult(step.stepNo(), decision(result.path("c1")),
                            decision(result.path("c2"))));
                }
            }
            results.add(new CaseResult(ruleCase.scenario(), ruleCase.classification(), stopped(stepResults),
                    stoppedBy(stepResults, StepResult::c1), stoppedBy(stepResults, StepResult::c2),
                    List.copyOf(stepResults)));
        }
        return List.copyOf(results);
    }

    /** The two rule controls under the settings and Contexa as recorded, over the cases with a ground truth. */
    static Map<String, Tally> tallies(List<RuleCases.Case> recorded, List<CaseResult> results) {
        Map<String, Tally> tallies = new LinkedHashMap<>();
        tallies.put("C1", tally(results, CaseResult::c1Stopped));
        tallies.put("C2", tally(results, CaseResult::c2Stopped));
        int attacks = 0;
        int attacksStopped = 0;
        int normals = 0;
        int normalsBlocked = 0;
        int normalsChecked = 0;
        int undecided = 0;
        for (RuleCases.Case ruleCase : recorded) {
            boolean threat = THREAT.equals(ruleCase.classification());
            boolean normal = NORMAL.equals(ruleCase.classification());
            if (!threat && !normal) {
                continue;
            }
            List<String> outcomes = ruleCase.steps().stream().map(RuleCases.CaseStep::contexaOutcome).toList();
            if (outcomes.isEmpty() || outcomes.stream().anyMatch(Objects::isNull)) {
                undecided++;
            } else if (threat) {
                attacks++;
                attacksStopped += outcomes.stream().anyMatch(outcome -> !DELIVERED.equals(outcome)) ? 1 : 0;
            } else {
                normals++;
                if (outcomes.stream().anyMatch(BLOCKING::contains)) {
                    normalsBlocked++;
                } else if (outcomes.contains(HELD)) {
                    normalsChecked++;
                }
            }
        }
        tallies.put("D", new Tally(attacks, attacksStopped, normals, normalsBlocked, normalsChecked, undecided));
        return tallies;
    }

    private static Tally tally(List<CaseResult> results, Function<CaseResult, Boolean> stopped) {
        int attacks = 0;
        int attacksStopped = 0;
        int normals = 0;
        int normalsBlocked = 0;
        int undecided = 0;
        for (CaseResult result : results) {
            boolean threat = THREAT.equals(result.classification());
            boolean normal = NORMAL.equals(result.classification());
            if (!threat && !normal) {
                continue;
            }
            Boolean value = stopped.apply(result);
            if (value == null) {
                undecided++;
            } else if (threat) {
                attacks++;
                attacksStopped += value ? 1 : 0;
            } else {
                normals++;
                normalsBlocked += value ? 1 : 0;
            }
        }
        return new Tally(attacks, attacksStopped, normals, normalsBlocked, 0, undecided);
    }

    /** The cases whose rule control result differs from the published settings', in the cases' order. */
    static List<Change> changes(List<CaseResult> before, List<CaseResult> now) {
        List<Change> changed = new ArrayList<>();
        for (int i = 0; i < now.size() && i < before.size(); i++) {
            CaseResult was = before.get(i);
            CaseResult is = now.get(i);
            if (!Objects.equals(was.c1Stopped(), is.c1Stopped())) {
                changed.add(new Change(is.scenario(), is.classification(), "C1", was.c1Stopped(), is.c1Stopped()));
            }
            if (!Objects.equals(was.c2Stopped(), is.c2Stopped())) {
                changed.add(new Change(is.scenario(), is.classification(), "C2", was.c2Stopped(), is.c2Stopped()));
            }
        }
        return List.copyOf(changed);
    }

    private static boolean refusedByRole(RuleCases.CaseStep step) {
        return ROLE_CHECK.equals(step.c1Rule()) || ROLE_CHECK.equals(step.c2Rule());
    }

    private static Decision decision(JsonNode node) {
        return new Decision(node.path("ruleId").isTextual() ? node.path("ruleId").asText() : null,
                node.path("allowed").isBoolean() ? node.path("allowed").asBoolean() : null,
                node.path("notRecorded").isTextual() ? node.path("notRecorded").asText() : null, false);
    }

    /** The same reading for one control's decisions. */
    static Boolean stoppedBy(List<StepResult> steps, Function<StepResult, Decision> control) {
        boolean unknown = false;
        for (StepResult step : steps) {
            Decision decision = control.apply(step);
            if (Boolean.FALSE.equals(decision.allowed())) {
                return true;
            }
            unknown |= decision.allowed() == null;
        }
        return unknown ? null : false;
    }

    /** Stopped when a control refused a request; unknown when a request could not be decided and none was refused. */
    static Boolean stopped(List<StepResult> steps) {
        boolean unknown = false;
        for (StepResult step : steps) {
            for (Decision decision : List.of(step.c1(), step.c2())) {
                if (Boolean.FALSE.equals(decision.allowed())) {
                    return true;
                }
                unknown |= decision.allowed() == null;
            }
        }
        return unknown ? null : false;
    }
}
