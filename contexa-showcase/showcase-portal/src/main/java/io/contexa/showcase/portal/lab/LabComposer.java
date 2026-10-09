package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Fact;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Step;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Turns a designed case and the conditions a visitor changed into the scenario definition the lab runs
 * (docs/showcase/데모-재설계.md 5A.1, 5A.1.1, W2-1). Unchanged, the case runs as designed, with its ground truth. Changed,
 * only the changed conditions are applied and the run has no ground truth (J-3): its oracle is {@link #COMPOSED} and the
 * rule controls' expected results are dropped, because the designed expectations may no longer hold.
 * <p>
 * Nothing is invented. A company record the visitor turns on is shaped like the same kind of record of a designed case
 * (approval as in A3T, incident ticket and on-call duty as in A8T, change ticket as in A5T, business trip as in A1T),
 * with the target project and that project's owner from the business database; a claimed ticket that does not exist is
 * the one case A8 claims. A record follows the target: when the target project changes, an approval or a covering
 * ticket names the new project. A multi-step case keeps its steps; only the conditions of the whole case change.
 */
public final class LabComposer {

    public static final String COMPOSED = "COMPOSED";
    static final List<String> ALL_ACTIONS = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    static final Set<BusinessOperation> OPERATIONS = Set.of(BusinessOperation.DOCUMENT_READ,
            BusinessOperation.DOCUMENT_DOWNLOAD, BusinessOperation.EXPORT, BusinessOperation.EXPORT_STREAM,
            BusinessOperation.EXPORT_ASYNC, BusinessOperation.CUSTOMER_READ, BusinessOperation.ROLE_GRANT);
    static final Set<BusinessOperation> EXPORTS = Set.of(BusinessOperation.EXPORT, BusinessOperation.EXPORT_STREAM,
            BusinessOperation.EXPORT_ASYNC);
    static final Set<BusinessOperation> DOCUMENTS = Set.of(BusinessOperation.DOCUMENT_READ,
            BusinessOperation.DOCUMENT_DOWNLOAD);

    public enum Place { OFFICE, TRAVEL, EXTERNAL }

    public enum Target { ASSIGNED, UNASSIGNED }

    public enum TicketChoice { NONE, COVERS, OTHER_PROJECT }

    public enum Claim { NONE, REAL, FAKE }

    /**
     * The conditions of a case. Read from a case, every field is set (the step fields only for a case of one step);
     * sent by a visitor, a null field keeps the case's value.
     */
    public record Conditions(String employee, TimeSlot timeSlot, Place place, ScenarioDefinition.Device device,
                             BusinessOperation operation, Target target, Integer items, Boolean approval,
                             TicketChoice ticket, Claim claim, Boolean onCall) {
    }

    /**
     * @param designed true when nothing was changed: the case runs as designed, with its ground truth
     * @param changed  the names of the changed conditions, in field order
     */
    public record Composed(ScenarioDefinition definition, boolean designed, List<String> changed,
                           Conditions conditions) {
    }

    /** A composition the lab cannot run; the reason is a stable code for the screen. */
    public static final class Refused extends IllegalArgumentException {
        private final String reason;

        public Refused(String reason) {
            super(reason);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }

    private final ScenarioCatalog catalog;
    private final ObjectMapper json;
    private final Fact approvalTemplate;
    private final Fact incidentTemplate;
    private final Fact changeTemplate;
    private final Fact onCallTemplate;
    private final Fact travelTemplate;
    private final Step grantTemplate;
    private final String unknownTicket;

    public LabComposer(ScenarioCatalog catalog, ObjectMapper json) {
        this.catalog = catalog;
        this.json = json.copy().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        this.approvalTemplate = fact("A3T", "APPROVAL", null);
        this.incidentTemplate = fact("A8T", "TICKET", "INCIDENT");
        this.changeTemplate = fact("A5T", "TICKET", "CHANGE");
        this.onCallTemplate = fact("A8T", "ONCALL", null);
        this.travelTemplate = fact("A1T", "TRAVEL", null);
        this.grantTemplate = designed("A5").steps().get(0);
        this.unknownTicket = Objects.requireNonNull(designed("A8").steps().get(0).claimedTicket(),
                "Case A8 claims a ticket");
    }

    /** The conditions of a designed case as the lab shows them before the visitor changes anything. */
    public Conditions conditions(ScenarioDefinition scenario, LabData data) {
        boolean single = scenario.steps().size() == 1;
        Step step = scenario.steps().get(0);
        String project = project(step);
        BusinessOperation operation = single ? step.operation() : null;
        Target target = !single ? null : project != null && data.assigned(scenario.protagonist(), project)
                ? Target.ASSIGNED : Target.UNASSIGNED;
        Integer items = single && EXPORTS.contains(step.operation()) ? step.items() : null;
        Fact ticket = first(scenario.facts(), "TICKET");
        TicketChoice ticketChoice = ticket == null ? TicketChoice.NONE
                : Objects.equals(ticket.project(), project) ? TicketChoice.COVERS : TicketChoice.OTHER_PROJECT;
        Claim claim = !single ? null : step.claimedTicket() == null ? Claim.NONE
                : step.claimedTicket().startsWith("{fact:") ? Claim.REAL : Claim.FAKE;
        return new Conditions(scenario.protagonist(), scenario.timeSlot(), place(scenario.networkOrDefault()),
                scenario.device(), operation, target, items, first(scenario.facts(), "APPROVAL") != null,
                ticketChoice, claim, first(scenario.facts(), "ONCALL") != null);
    }

    /** The definition the lab runs for a designed case and the conditions a visitor sent. */
    public Composed compose(String caseKey, Conditions requested, LabData data) {
        ScenarioDefinition scenario = catalog.find(caseKey).orElseThrow(() -> new Refused("UNKNOWN_CASE"));
        Conditions base = conditions(scenario, data);
        List<String> changed = changed(base, requested);
        if (changed.isEmpty()) {
            return new Composed(scenario, true, List.of(), base);
        }
        boolean single = scenario.steps().size() == 1;
        if (!single && changed.stream().anyMatch(Set.of("operation", "target", "items", "claim")::contains)) {
            throw new Refused("STEPS_FIXED");
        }
        Conditions effective = merge(base, requested);
        validate(effective, single, changed, data);

        List<Step> steps;
        String project;
        if (single) {
            Step step = step(scenario.steps().get(0), effective, data);
            project = project(step);
            steps = List.of(step);
        } else {
            project = scenario.steps().stream().map(LabComposer::project).filter(Objects::nonNull).findFirst()
                    .orElse(null);
            steps = scenario.steps().stream().map(LabComposer::withoutExpectation).toList();
        }
        if (project == null && (Boolean.TRUE.equals(effective.approval()) || effective.ticket() == TicketChoice.COVERS)) {
            throw new Refused("NO_PROJECT_FOR_RECORD");
        }
        List<Fact> facts = facts(scenario, effective, project, steps, data);
        if (single) {
            steps = List.of(claimed(steps.get(0), effective.claim(), facts));
        }
        ScenarioDefinition composed = new ScenarioDefinition("LAB", 1,
                Map.of("ko", scenario.title().get("ko") + " · 조건 변경", "en",
                        scenario.title().get("en") + " · changed conditions"),
                effective.employee(), scenario.template(), effective.timeSlot(), effective.device(), scenario.pace(),
                facts, steps, new ScenarioDefinition.Oracle(COMPOSED, ALL_ACTIONS), network(effective.place()));
        String key = "LAB-" + sha256(write(composed)).substring(0, 12);
        return new Composed(new ScenarioDefinition(key, composed.version(), composed.title(), composed.protagonist(),
                composed.template(), composed.timeSlot(), composed.device(), composed.pace(), composed.facts(),
                composed.steps(), composed.oracle(), composed.network()), false, changed, effective);
    }

    static List<String> changed(Conditions base, Conditions requested) {
        List<String> changed = new ArrayList<>();
        if (requested == null) {
            return changed;
        }
        differs(changed, "employee", base.employee(), requested.employee());
        differs(changed, "timeSlot", base.timeSlot(), requested.timeSlot());
        differs(changed, "place", base.place(), requested.place());
        differs(changed, "device", base.device(), requested.device());
        differs(changed, "operation", base.operation(), requested.operation());
        differs(changed, "target", base.target(), requested.target());
        differs(changed, "items", base.items(), requested.items());
        differs(changed, "approval", base.approval(), requested.approval());
        differs(changed, "ticket", base.ticket(), requested.ticket());
        differs(changed, "claim", base.claim(), requested.claim());
        differs(changed, "onCall", base.onCall(), requested.onCall());
        return changed;
    }

    private static void differs(List<String> changed, String name, Object base, Object requested) {
        if (requested != null && !requested.equals(base)) {
            changed.add(name);
        }
    }

    private static Conditions merge(Conditions base, Conditions requested) {
        return new Conditions(pick(requested.employee(), base.employee()), pick(requested.timeSlot(), base.timeSlot()),
                pick(requested.place(), base.place()), pick(requested.device(), base.device()),
                pick(requested.operation(), base.operation()), pick(requested.target(), base.target()),
                pick(requested.items(), base.items()), pick(requested.approval(), base.approval()),
                pick(requested.ticket(), base.ticket()), pick(requested.claim(), base.claim()),
                pick(requested.onCall(), base.onCall()));
    }

    private static <T> T pick(T requested, T base) {
        return requested != null ? requested : base;
    }

    /** A designed value always stands; a changed value must be one of the lab's choices. */
    private static void validate(Conditions conditions, boolean single, List<String> changed, LabData data) {
        if (!data.employees().containsKey(conditions.employee())) {
            throw new Refused("UNKNOWN_EMPLOYEE");
        }
        if (single && !OPERATIONS.contains(conditions.operation())) {
            throw new Refused("UNKNOWN_OPERATION");
        }
        if (single && EXPORTS.contains(conditions.operation()) && (conditions.items() == null
                || (changed.contains("items") || changed.contains("operation"))
                && !Combination.ITEMS.contains(conditions.items()))) {
            throw new Refused("UNKNOWN_ITEMS");
        }
        if (conditions.claim() == Claim.REAL && conditions.ticket() == TicketChoice.NONE) {
            throw new Refused("CLAIM_NEEDS_TICKET");
        }
    }

    /** The one step of a single-step case under the effective conditions; unchanged parts stay as designed. */
    private Step step(Step designed, Conditions conditions, LabData data) {
        BusinessOperation operation = conditions.operation();
        Integer items = EXPORTS.contains(operation) ? conditions.items() : null;
        return switch (operation) {
            case CUSTOMER_READ -> new Step(operation, null, null, customer(designed, conditions, data), null, 0,
                    Map.of(), null, null, null, null);
            case ROLE_GRANT -> new Step(operation, null, project(designed, conditions, data), null, null, 0,
                    Map.of(), null, grantTemplate.grantee(), grantTemplate.responsibility(), null);
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD -> {
                String project = project(designed, conditions, data);
                yield new Step(operation, document(designed, project, data), null, null, null, 0, Map.of(), null,
                        null, null, null);
            }
            default -> new Step(operation, null, project(designed, conditions, data), null, items, 0, Map.of(),
                    null, null, null, null);
        };
    }

    /** The designed project when it still has the chosen relation to the employee, otherwise the database's first. */
    private static String project(Step designed, Conditions conditions, LabData data) {
        String designedProject = project(designed);
        boolean wantAssigned = conditions.target() == Target.ASSIGNED;
        if (designedProject != null && data.assigned(conditions.employee(), designedProject) == wantAssigned) {
            return designedProject;
        }
        if (wantAssigned) {
            List<String> assigned = data.assignments().getOrDefault(conditions.employee(), List.of());
            if (assigned.isEmpty()) {
                throw new Refused("NO_ASSIGNED_PROJECT");
            }
            return assigned.get(0);
        }
        return data.projects().keySet().stream().filter(key -> !data.assigned(conditions.employee(), key))
                .findFirst().orElseThrow(() -> new Refused("NO_UNASSIGNED_PROJECT"));
    }

    private static String customer(Step designed, Conditions conditions, LabData data) {
        if (conditions.target() == Target.ASSIGNED) {
            // The business database assigns no customer to the lab's employees (5A.1.1): there is nothing to pick.
            data.customers().stream().filter(customer -> customer.accountManager().equals(conditions.employee()))
                    .findFirst().orElseThrow(() -> new Refused("NO_ASSIGNED_CUSTOMER"));
        }
        if (designed.customer() != null) {
            return designed.customer();
        }
        return data.customers().stream().filter(customer -> !customer.accountManager().equals(conditions.employee()))
                .map(LabData.Customer::key).findFirst().orElseThrow(() -> new Refused("NO_CUSTOMER"));
    }

    /**
     * The designed document, or in another project the document of the designed type at the designed position when
     * that project has the type (the same kind of request for another employee, W2-7); otherwise the first document of
     * the project's first type.
     */
    private static ScenarioDefinition.DocumentSelector document(Step designed, String project, LabData data) {
        if (designed.document() != null && designed.document().project().equals(project)) {
            return designed.document();
        }
        List<String> types = data.documentTypes().getOrDefault(project, List.of());
        if (types.isEmpty()) {
            throw new Refused("NO_DOCUMENT");
        }
        if (designed.document() != null && designed.document().fact() == null
                && types.contains(designed.document().type())) {
            return new ScenarioDefinition.DocumentSelector(project, designed.document().type(),
                    designed.document().position());
        }
        return new ScenarioDefinition.DocumentSelector(project, types.get(0), 1);
    }

    /** The company records of the composed case; a record left as designed keeps its designed values. */
    private List<Fact> facts(ScenarioDefinition scenario, Conditions conditions, String project, List<Step> steps,
                             LabData data) {
        List<Fact> facts = new ArrayList<>();
        for (Fact fact : scenario.facts()) {
            switch (fact.kind()) {
                case "TRAVEL" -> {
                    if (conditions.place() == Place.TRAVEL) {
                        facts.add(fact);
                    }
                }
                case "APPROVAL" -> {
                    if (Boolean.TRUE.equals(conditions.approval())) {
                        facts.add(forProject(fact, project, data, fact.maxItems()));
                    }
                }
                case "TICKET" -> {
                    if (conditions.ticket() != TicketChoice.NONE) {
                        facts.add(ticketFor(fact, conditions.ticket(), project, data));
                    }
                }
                case "ONCALL" -> {
                    if (Boolean.TRUE.equals(conditions.onCall())) {
                        facts.add(fact);
                    }
                }
                default -> facts.add(fact);
            }
        }
        if (conditions.place() == Place.TRAVEL && first(facts, "TRAVEL") == null) {
            facts.add(travelTemplate);
        }
        if (Boolean.TRUE.equals(conditions.approval()) && first(facts, "APPROVAL") == null) {
            Integer items = steps.stream().map(Step::items).filter(Objects::nonNull).max(Integer::compare)
                    .orElse(approvalTemplate.maxItems());
            facts.add(forProject(approvalTemplate, project, data, items));
        }
        if (conditions.ticket() != TicketChoice.NONE && first(facts, "TICKET") == null) {
            Fact template = conditions.operation() == BusinessOperation.ROLE_GRANT ? changeTemplate : incidentTemplate;
            facts.add(ticketFor(template, conditions.ticket(), project, data));
        }
        if (Boolean.TRUE.equals(conditions.onCall()) && first(facts, "ONCALL") == null) {
            facts.add(onCallTemplate);
        }
        return facts;
    }

    private static Fact ticketFor(Fact template, TicketChoice choice, String project, LabData data) {
        String target = choice == TicketChoice.COVERS ? project
                : data.projects().keySet().stream().filter(key -> !key.equals(project)).findFirst()
                .orElseThrow(() -> new Refused("NO_OTHER_PROJECT"));
        return forProject(template, target, data, template.maxItems());
    }

    private static Fact forProject(Fact template, String project, LabData data, Integer maxItems) {
        LabData.Project row = data.projects().get(project);
        String approver = row == null || row.owner() == null || row.owner().isBlank() ? template.approver()
                : row.owner();
        return new Fact(template.kind(), template.ticketKind(), approver, project, template.purpose(), maxItems,
                template.validFromOffset(), template.validUntilOffset(), template.status(), template.team(),
                template.city(), template.country(), template.network(), template.document(),
                template.recordedAtOffset());
    }

    /** The ticket the request names: none, the run's real ticket record, or the number case A8 claims. */
    private Step claimed(Step step, Claim claim, List<Fact> facts) {
        String claimedTicket = switch (claim == null ? Claim.NONE : claim) {
            case NONE -> null;
            case REAL -> "{fact:" + (facts.indexOf(first(facts, "TICKET")) + 1) + "}";
            case FAKE -> unknownTicket;
        };
        return new Step(step.operation(), step.document(), step.project(), step.customer(), step.items(),
                step.offsetSeconds(), Map.of(), claimedTicket, step.grantee(), step.responsibility(),
                step.visitorSends());
    }

    private static Step withoutExpectation(Step step) {
        return new Step(step.operation(), step.document(), step.project(), step.customer(), step.items(),
                step.offsetSeconds(), Map.of(), step.claimedTicket(), step.grantee(), step.responsibility(),
                step.visitorSends());
    }

    private static String project(Step step) {
        return step.project() != null ? step.project() : step.document() != null ? step.document().project() : null;
    }

    private static Fact first(List<Fact> facts, String kind) {
        return facts.stream().filter(fact -> kind.equals(fact.kind())).findFirst().orElse(null);
    }

    private static Place place(ScenarioDefinition.Network network) {
        return switch (network) {
            case OFFICE -> Place.OFFICE;
            case TRAVEL -> Place.TRAVEL;
            case EXTERNAL -> Place.EXTERNAL;
        };
    }

    private static ScenarioDefinition.Network network(Place place) {
        return switch (place) {
            case OFFICE -> ScenarioDefinition.Network.OFFICE;
            case TRAVEL -> ScenarioDefinition.Network.TRAVEL;
            case EXTERNAL -> ScenarioDefinition.Network.EXTERNAL;
        };
    }

    private ScenarioDefinition designed(String key) {
        return catalog.find(key).orElseThrow(() -> new IllegalStateException("Designed case missing: " + key));
    }

    private Fact fact(String caseKey, String kind, String ticketKind) {
        return designed(caseKey).facts().stream().filter(fact -> kind.equals(fact.kind()))
                .filter(fact -> ticketKind == null || ticketKind.equals(fact.ticketKind())).findFirst()
                .orElseThrow(() -> new IllegalStateException("Case " + caseKey + " has no " + kind + " record"));
    }

    private String write(ScenarioDefinition definition) {
        try {
            Map<String, Object> tree = json.convertValue(definition, LinkedHashMap.class);
            return json.writeValueAsString(tree);
        } catch (Exception e) {
            throw new IllegalStateException("Unwritable composed definition", e);
        }
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
