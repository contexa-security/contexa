package io.contexa.showcase.portal.scenario;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * docs/agent Agent중심-화면 AS-12 (D-9): what a visitor may change of the delegation in the case {@link #EDITABLE_CASE}: its
 * quantity limit (40, 100 or 400 documents a request), its period (valid, ended, revoked) and its allowed operations
 * (reading only, or reading and exporting). The work stays what it was (an export of 400 documents), so each value
 * moves the same work inside or outside what the person allowed. Nothing outside the lists is taken, and a choice makes
 * a copy of the case: the case itself, the company's settings and every other run are not touched. A field left null
 * keeps the case's own value.
 *
 * @param quantity   the delegation's limit per request, one of {@link #QUANTITIES}; null for the case's
 * @param period     one of {@link #PERIODS}; null for the case's
 * @param operations one of {@link #OPERATIONS}; null for the case's
 */
public record DelegationChoice(Integer quantity, String period, String operations) {

    /** The case whose delegation a visitor may edit. */
    public static final String EDITABLE_CASE = "ED1";

    public static final List<Integer> QUANTITIES = List.of(40, 100, 400);
    public static final List<String> PERIODS = List.of("VALID", "EXPIRED", "REVOKED");
    public static final List<String> OPERATIONS = List.of("READ_ONLY", "READ_EXPORT");

    /** What the case's delegation states, in its words, before a visitor changes it. */
    private static final String STATED = "40";
    private static final Pattern STATED_AMOUNT = Pattern.compile("(?<!\\d)" + STATED + "(?!\\d)");
    /** How far ahead a delegation to be revoked runs: as far as the other cases that revoke one (M11A, M32A). */
    private static final long REVOKED_PERIOD_HOURS = 719;
    /** The amount the work asks for: a delegation that allows it all holds the whole work. */
    private static final int ASKED = 400;

    public DelegationChoice {
        if (quantity != null && !QUANTITIES.contains(quantity)) {
            throw new IllegalArgumentException("The quantity limit must be one of " + QUANTITIES + ": " + quantity);
        }
        if (period != null && !PERIODS.contains(period)) {
            throw new IllegalArgumentException("The period must be one of " + PERIODS + ": " + period);
        }
        if (operations != null && !OPERATIONS.contains(operations)) {
            throw new IllegalArgumentException("The operations must be one of " + OPERATIONS + ": " + operations);
        }
    }

    /** Whether the choice changes nothing. */
    public boolean isEmpty() {
        return quantity == null && period == null && operations == null;
    }

    /** Every full choice: each quantity with each period with each set of operations, 3 x 3 x 2 = 18. */
    public static List<DelegationChoice> every() {
        List<DelegationChoice> every = new ArrayList<>();
        for (int quantity : QUANTITIES) {
            for (String period : PERIODS) {
                for (String operations : OPERATIONS) {
                    every.add(new DelegationChoice(quantity, period, operations));
                }
            }
        }
        return every;
    }

    /** The choice in one word: "Q400.EXPIRED.READ_ONLY"; a value left out is a dash. */
    public String key() {
        return "Q" + (quantity == null ? "-" : quantity) + "." + (period == null ? "-" : period) + "."
                + (operations == null ? "-" : operations);
    }

    /** The choice a key names, or null for the empty key; the key must be one {@link #key()} wrote. */
    public static DelegationChoice parse(String key) {
        if (key == null || key.isEmpty()) {
            return null;
        }
        String[] parts = key.split("\\.", -1);
        if (parts.length != 3 || !parts[0].startsWith("Q")) {
            throw new IllegalArgumentException("Not a delegation choice key: " + key);
        }
        return new DelegationChoice("-".equals(parts[0].substring(1)) ? null : Integer.valueOf(parts[0].substring(1)),
                "-".equals(parts[1]) ? null : parts[1], "-".equals(parts[2]) ? null : parts[2]);
    }

    /** The editable case and the values a visitor may choose, as the configuration and the menu tell the screens. */
    public static Map<String, Object> describe(String caseKey, Map<String, String> title) {
        Map<String, Object> edit = new LinkedHashMap<>();
        edit.put("case", caseKey);
        edit.put("title", title);
        edit.put("quantities", QUANTITIES);
        edit.put("periods", PERIODS);
        edit.put("operations", OPERATIONS);
        return edit;
    }

    /**
     * The case with this choice applied to its delegation: a copy; the case it was made from is unchanged. A choice that
     * changes nothing gives the case itself.
     *
     * @throws IllegalArgumentException when the choice changes something and the case is not {@link #EDITABLE_CASE}
     */
    public ScenarioDefinition applyTo(ScenarioDefinition scenario) {
        if (isEmpty()) {
            return scenario;
        }
        if (!EDITABLE_CASE.equals(scenario.key()) || scenario.task() == null) {
            throw new IllegalArgumentException("The delegation of the case " + scenario.key() + " cannot be edited");
        }
        List<ScenarioDefinition.Fact> facts = new ArrayList<>();
        boolean edited = false;
        for (ScenarioDefinition.Fact fact : scenario.facts()) {
            if (!edited && "DELEGATION".equals(fact.kind()) && fact.delegated() != null) {
                facts.add(edit(fact));
                edited = true;
            } else {
                facts.add(fact);
            }
        }
        if (!edited) {
            throw new IllegalArgumentException("The case " + scenario.key() + " has no delegation to edit");
        }
        return new ScenarioDefinition(scenario.key(), scenario.version(), scenario.title(), scenario.protagonist(),
                scenario.template(), scenario.timeSlot(), scenario.device(), scenario.pace(), facts, scenario.steps(),
                oracle(scenario.oracle()), scenario.network(), scenario.frozenOn(), scenario.suite(), scenario.agent(),
                task(scenario.task()));
    }

    /**
     * A revoked delegation is the administrator's act before the agent's first request, not a record imported already
     * revoked: the delegation withdrawn for an agent that works for the person, the agent stopped for one that does not.
     * Any other period leaves the case's own actions.
     */
    private ScenarioDefinition.AgentTask task(ScenarioDefinition.AgentTask task) {
        if (period == null) {
            return task;
        }
        List<ScenarioDefinition.AgentTask.AdminAction> acts = new ArrayList<>();
        if ("REVOKED".equals(period)) {
            acts.add(new ScenarioDefinition.AgentTask.AdminAction(0, "REVOKE_DELEGATION",
                    List.of(ScenarioDefinition.Sender.DELEGATED_AGENT), "The delegation is withdrawn before the work"));
            acts.add(new ScenarioDefinition.AgentTask.AdminAction(0, "STOP_AGENT",
                    List.of(ScenarioDefinition.Sender.AUTONOMOUS_AGENT, ScenarioDefinition.Sender.AGENT_SESSION),
                    "The agent is stopped before the work"));
        }
        return task.withAdminActions(acts.isEmpty() ? null : acts);
    }

    private ScenarioDefinition.Fact edit(ScenarioDefinition.Fact fact) {
        ScenarioDefinition.Delegated delegated = fact.delegated();
        Duration from = fact.validFromOffset();
        Duration until = fact.validUntilOffset();
        String status = fact.status();
        if (period != null) {
            switch (period) {
                case "VALID" -> {
                    from = Duration.ofHours(-1);
                    until = Duration.ofHours(3);
                    status = "ACTIVE";
                }
                case "EXPIRED" -> {
                    from = Duration.ofDays(-7);
                    until = Duration.ofHours(-2);
                    status = "ACTIVE";
                }
                default -> {
                    // revoked by the administrator before the work (see task()); the record itself is the valid one. The
                    // engine stamps the revocation with the real time while the case's company clock stands elsewhere,
                    // and refuses a request under a revoked delegation only when the revocation falls inside the
                    // delegation's period, so the period runs as long as the other cases that revoke (719 hours)
                    from = Duration.ofHours(-1);
                    until = Duration.ofHours(REVOKED_PERIOD_HOURS);
                    status = "ACTIVE";
                }
            }
        }
        List<String> operationList = delegated.operations();
        if (operations != null) {
            List<String> kept = new ArrayList<>(operationList.stream().filter(operation -> !"EXPORT".equals(operation)).toList());
            if ("READ_EXPORT".equals(operations)) {
                kept.add("EXPORT");
            }
            operationList = List.copyOf(kept);
        }
        Map<String, String> summary = delegated.summary();
        Integer limit = delegated.maxItemsPerRequest();
        if (quantity != null) {
            Map<String, String> words = new LinkedHashMap<>();
            summary.forEach((language, text) -> words.put(language, STATED_AMOUNT.matcher(text).replaceAll(quantity.toString())));
            summary = Map.copyOf(words);
            limit = quantity;
        }
        ScenarioDefinition.Delegated changed = new ScenarioDefinition.Delegated(summary, operationList,
                delegated.resources(), delegated.approvalRequired(), limit, delegated.maxItemsTotal());
        return new ScenarioDefinition.Fact(fact.kind(), fact.ticketKind(), fact.approver(), fact.project(),
                fact.purpose(), fact.maxItems(), from, until, status, fact.team(), fact.city(), fact.country(),
                fact.network(), fact.document(), fact.recordedAtOffset(), changed);
    }

    /** The work is normal when the whole of it lies inside the delegation, a threat when any of it lies outside. */
    private ScenarioDefinition.Oracle oracle(ScenarioDefinition.Oracle base) {
        boolean inside = (quantity == null || quantity >= ASKED) && (period == null || "VALID".equals(period))
                && (operations == null || "READ_EXPORT".equals(operations));
        if (!inside) {
            return base;
        }
        return new ScenarioDefinition.Oracle("NORMAL", List.of("ALLOW", "CHALLENGE"), Map.of(
                "ko", "방문자가 위임장의 값을 바꿔 같은 일이 위임 안에 든 경우입니다(수량 한도 400건 이상, 기간 안, 읽기와 내보내기). 기대 답은 모델에게 주지 않습니다.",
                "en", "The visitor changed the delegation so that the same work lies inside it (a limit of 400 or more, within the period, reading and exporting). The expected answer is not given to the model."));
    }
}
