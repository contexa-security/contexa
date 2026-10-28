package io.contexa.showcase.portal.scenario;

import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The history an agent of a case brings, so that it is not a stranger on the day of the case (docs/agent RL-3). Every
 * run registers a new agent, and a new agent has no baseline: in the A6 measurement 56% of the delegated, 80% of the
 * standalone and 95% of the session agent's decisions read "baseline not established", where a person starts from a
 * learned template. A history profile gives the agent the days of usual work an agent of that kind has behind it:
 * the same requests, in the same order, on each of the days before the case, sent on the same path as the case's own
 * work, so the engine learns them as it learns any agent's requests. It adds no rule and no fact the engine does not
 * learn on its own. Each day is a session of its own, signed in again as a person's days are: a history in one session
 * of six days would teach the engine one login only, and the case's first session of its own would read as a stranger's.
 * An agent that acts for a person is preceded by the person's own first request. A case that works in the person's own
 * session has no history: it has the person's baseline already.
 * <p>
 * The history is the agent's usual work: the operations its tools offer that its delegation allows, nothing a case
 * would call out of the ordinary (no customers, no role grants, no deletions, no downloads).
 */
public final class AgentHistory {

    /** The profile: six days of listing, a few reads and an export of the usual amount. */
    public static final String USUAL_WORK = "USUAL_WORK";

    static final int DAYS = 6;
    static final int READS_PER_DAY = 3;
    static final int USUAL_EXPORT_ITEMS = 40;
    static final String DEFAULT_PROJECT = "HX-310";
    static final String READ_TYPE = "DRAWING";
    private static final long DAY_SECONDS = Duration.ofDays(1).toSeconds();
    /** The longest the engine lets a delegation last (its default, 30 days): the history may not stretch one past it. */
    static final Duration LONGEST_DELEGATION = Duration.ofDays(30);
    /** The operations a history repeats, in the order of a working day. */
    private static final List<BusinessOperation> USUAL = List.of(BusinessOperation.DOCUMENT_LIST,
            BusinessOperation.DOCUMENT_READ, BusinessOperation.EXPORT);

    private AgentHistory() {
    }

    /** Whether the profile is one this class knows. */
    public static boolean known(String profile) {
        return USUAL_WORK.equals(profile);
    }

    /**
     * The case with the history of the profile before it: the steps of the days before the case, and the delegation
     * of the case valid from before the first of them.
     *
     * @throws IllegalArgumentException when the profile is unknown or the case has no agent task
     */
    public static ScenarioDefinition apply(ScenarioDefinition scenario, String profile) {
        if (!known(profile)) {
            throw new IllegalArgumentException("Unknown history profile " + profile);
        }
        if (scenario.task() == null || scenario.agent() == null) {
            throw new IllegalArgumentException("Only an agent task case has a history");
        }
        ScenarioDefinition.Sender sender = scenario.task().sender();
        if (!hasAgentBaseline(sender)) {
            return scenario;
        }
        Set<BusinessOperation> usual = usualOperations(scenario);
        if (usual.isEmpty() || outlastsTheLimit(scenario)) {
            return scenario;
        }
        String project = projectOf(scenario);
        List<ScenarioDefinition.Step> steps = new ArrayList<>();
        if (actsForAPerson(sender)) {
            // The engine asks a person for the one-time code at a sign-in only when the person has no earlier ALLOW.
            // A person who has an agent has work of their own before it: the agent's requests alone would leave every
            // day's sign-in with a code, and the case's own day, after the person's own ALLOW, without one.
            steps.add(step(BusinessOperation.DOCUMENT_LIST, null, project, null, -DAYS * DAY_SECONDS - 60, null));
        }
        for (int day = 0; day < DAYS; day++) {
            long base = -(DAYS - day) * DAY_SECONDS;
            long at = base;
            int dayStart = steps.size();
            if (usual.contains(BusinessOperation.DOCUMENT_LIST)) {
                steps.add(step(BusinessOperation.DOCUMENT_LIST, null, project, null, at, sender));
                at += 60;
            }
            if (usual.contains(BusinessOperation.DOCUMENT_READ)) {
                for (int position = 1; position <= READS_PER_DAY; position++) {
                    steps.add(step(BusinessOperation.DOCUMENT_READ,
                            new ScenarioDefinition.DocumentSelector(project, READ_TYPE, position), project, null, at,
                            sender));
                    at += 60;
                }
            }
            if (usual.contains(BusinessOperation.EXPORT)) {
                steps.add(step(BusinessOperation.EXPORT, null, project, USUAL_EXPORT_ITEMS, at, sender));
            }
            // Each day is a session of its own, as a person's days are. The run's own sign-in is the first step's: the
            // agent's first day signs in again only when a person's step comes first (an agent that acts for a person
            // signs in after the person's own ALLOW, as every later day does, so that all days read the same way).
            if (day > 0 || actsForAPerson(sender)) {
                steps.set(dayStart, steps.get(dayStart).startingSession());
            }
        }
        // The case's day is a new day too: its first step, or when it has none the agent's work, signs in again.
        ScenarioDefinition.AgentTask task = scenario.task();
        if (scenario.steps().isEmpty()) {
            task = task.startingSession();
        } else {
            steps.addAll(scenario.steps());
            int caseStart = steps.size() - scenario.steps().size();
            steps.set(caseStart, steps.get(caseStart).startingSession());
        }
        Duration earliest = Duration.ofSeconds(-DAYS * DAY_SECONDS - 3600);
        List<ScenarioDefinition.Fact> facts = scenario.facts().stream()
                .map(fact -> startsBefore(fact, earliest)).toList();
        return new ScenarioDefinition(scenario.key(), scenario.version(), scenario.title(), scenario.protagonist(),
                scenario.template(), scenario.timeSlot(), scenario.device(), scenario.pace(), facts, steps,
                scenario.oracle(), scenario.network(), scenario.frozenOn(), scenario.suite(), scenario.agent(), task);
    }

    /**
     * Whether the sender learns a baseline of its own: the agent with a token of its own or an account of its own. The
     * agent that works in the person's own session has the person's baseline (a learned template), and the engine's
     * internal client is no agent at all.
     */
    private static boolean hasAgentBaseline(ScenarioDefinition.Sender sender) {
        return sender == ScenarioDefinition.Sender.DELEGATED_AGENT || sender == ScenarioDefinition.Sender.DELEGATED_RELAY
                || sender == ScenarioDefinition.Sender.AUTONOMOUS_AGENT || sender == ScenarioDefinition.Sender.AGENT_SESSION;
    }

    /**
     * Whether the history would stretch a delegation of the case past the longest the engine allows: it moves the start of
     * a delegation back to before the first day, so one that already lasts the limit would last longer. Such a case gets
     * no history rather than a changed delegation, since it is about a delegation of that length.
     */
    private static boolean outlastsTheLimit(ScenarioDefinition scenario) {
        Duration earliest = Duration.ofSeconds(-DAYS * DAY_SECONDS - 3600);
        return scenario.facts().stream()
                .filter(fact -> "DELEGATION".equals(fact.kind()) && fact.validFromOffset() != null
                        && fact.validUntilOffset() != null)
                .anyMatch(fact -> fact.validUntilOffset().minus(fact.validFromOffset().compareTo(earliest) < 0
                        ? fact.validFromOffset() : earliest).compareTo(LONGEST_DELEGATION) > 0);
    }

    /** Whether the agent's token is the exchange of a person's own sign-in (the agent acts for the person). */
    private static boolean actsForAPerson(ScenarioDefinition.Sender sender) {
        return sender == ScenarioDefinition.Sender.DELEGATED_AGENT || sender == ScenarioDefinition.Sender.DELEGATED_RELAY;
    }

    /** The operations of the history: the tools the agent has and its delegation allows, among the usual ones. */
    static Set<BusinessOperation> usualOperations(ScenarioDefinition scenario) {
        Set<BusinessOperation> usual = new LinkedHashSet<>();
        List<String> delegated = scenario.facts().stream()
                .filter(fact -> "DELEGATION".equals(fact.kind()) && fact.delegated() != null)
                .flatMap(fact -> fact.delegated().operations().stream()).toList();
        for (BusinessOperation operation : USUAL) {
            if (scenario.task().tools().contains(operation)
                    && (delegated.isEmpty() || delegated.contains(operation.name()))) {
                usual.add(operation);
            }
        }
        return usual;
    }

    private static String projectOf(ScenarioDefinition scenario) {
        return scenario.facts().stream()
                .filter(fact -> "DELEGATION".equals(fact.kind()) && fact.project() != null)
                .map(ScenarioDefinition.Fact::project).findFirst()
                .or(() -> scenario.steps().stream().map(ScenarioDefinition.Step::project)
                        .filter(project -> project != null && !project.isBlank()).findFirst())
                .orElse(DEFAULT_PROJECT);
    }

    private static ScenarioDefinition.Step step(BusinessOperation operation, ScenarioDefinition.DocumentSelector document,
                                               String project, Integer items, long offsetSeconds,
                                               ScenarioDefinition.Sender sender) {
        return new ScenarioDefinition.Step(operation, document, project, null, items, offsetSeconds, null, null, null,
                null, null, null, null, null, null, sender);
    }

    /** A delegation that started after the history began starts before it; any other fact stays. */
    private static ScenarioDefinition.Fact startsBefore(ScenarioDefinition.Fact fact, Duration earliest) {
        if (!"DELEGATION".equals(fact.kind()) || fact.validFromOffset() == null
                || fact.validFromOffset().compareTo(earliest) <= 0) {
            return fact;
        }
        return new ScenarioDefinition.Fact(fact.kind(), fact.ticketKind(), fact.approver(), fact.project(),
                fact.purpose(), fact.maxItems(), earliest, fact.validUntilOffset(), fact.status(), fact.team(),
                fact.city(), fact.country(), fact.network(), fact.document(), fact.recordedAtOffset(),
                fact.delegated());
    }
}
