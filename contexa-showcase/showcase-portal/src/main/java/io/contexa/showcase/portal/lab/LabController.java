package io.contexa.showcase.portal.lab;

import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.RbacPolicy;
import io.contexa.showcase.portal.anatomy.BeforeSend;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.live.LiveGate;
import io.contexa.showcase.portal.live.LiveRuns;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The lab's visitor endpoints (docs/showcase/데모-재설계.md 5.3, 5A.1, W2-3): the choices as the business database and
 * the designed cases hold them, a run of a composed case with the visitor's call sent before it starts, the visitor's
 * assessment of a decision (only the run's own visitor, once per step) and the visitor's recent lab runs for the
 * comparison with the previous one. A run goes through the live runs' cost gate unchanged.
 */
@RestController
@ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
public class LabController {

    static final Pattern RUN_ID = Pattern.compile("run-[0-9a-f]{12}");
    static final Duration OPTIONS_CACHE = Duration.ofMinutes(5);

    public record StartRequest(String caseKey, LabComposer.Conditions conditions, PredictionRequest prediction,
                               String turnstileToken) {
    }

    public record PredictionRequest(String call, Map<String, String> approaches) {
    }

    /** @param step the request of the case to compare; 1 when absent */
    public record BeforeRequest(String caseKey, LabComposer.Conditions conditions, Integer step) {
    }

    public record AssessmentRequest(String verdict, List<String> reasons) {
    }

    private final LabComposer composer;
    private final LabStore store;
    private final LiveGate gate;
    private final LiveRuns live;
    private final ScenarioCatalog catalog;
    private final WorkloadAdmin admin;
    private final VisitorCookies cookies;
    private final BeforeSend before;
    private final Clock clock = Clock.systemUTC();
    private LabData cachedData;
    private Instant cachedAt;

    public LabController(LabComposer composer, LabStore store, LiveGate gate, LiveRuns live, ScenarioCatalog catalog,
                         WorkloadAdmin admin, VisitorCookies cookies, BeforeSend before) {
        this.composer = composer;
        this.before = before;
        this.store = store;
        this.gate = gate;
        this.live = live;
        this.catalog = catalog;
        this.admin = admin;
        this.cookies = cookies;
    }

    /** Every choice of the lab with where it comes from; nothing is offered that the data does not hold. */
    @GetMapping("/api/lab/options")
    public ResponseEntity<Map<String, Object>> options() {
        LabData data;
        try {
            data = data();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        List<Map<String, Object>> employees = new ArrayList<>();
        for (String key : data.employees().keySet()) {
            LabData.Employee employee = data.employees().get(key);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("key", key);
            row.put("role", employee.role());
            row.put("displayName", employee.displayName());
            row.put("department", employee.department());
            row.put("officeNetwork", employee.officeNetwork());
            row.put("assignedProjects", data.assignments().getOrDefault(key, List.of()));
            row.put("customersManaged", data.customers().stream()
                    .filter(customer -> key.equals(customer.accountManager())).count());
            Map<String, Boolean> allowed = new LinkedHashMap<>();
            for (BusinessOperation operation : LabComposer.OPERATIONS.stream().sorted().toList()) {
                allowed.put(operation.name(), RbacPolicy.RULES.stream()
                        .filter(rule -> rule.operation() == operation).findFirst()
                        .map(rule -> rule.allows(employee.role())).orElse(false));
            }
            row.put("roleAllows", allowed);
            employees.add(row);
        }
        List<Map<String, Object>> slots = new ArrayList<>();
        for (TimeSlot slot : TimeSlot.values()) {
            slots.add(Map.of("slot", slot.name(), "representativeTime", slot.representativeTime().toString()));
        }
        List<Map<String, Object>> cases = new ArrayList<>();
        for (ScenarioDefinition scenario : catalog.all()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("key", scenario.key());
            row.put("version", scenario.version());
            row.put("title", scenario.title());
            row.put("classification", scenario.oracle().classification());
            row.put("steps", scenario.steps().size());
            row.put("conditions", composer.conditions(scenario, data));
            // The company records the case puts in the business database (an approval, a ticket, a duty), so a
            // screen states them as the case defines them instead of copying them.
            row.put("facts", scenario.facts());
            // What each request of the case asks for, so a screen states the request as defined. The rule controls'
            // expected answers stay out: they would show results before the visitor's call (review R-25).
            List<Map<String, Object>> requests = new ArrayList<>();
            for (ScenarioDefinition.Step step : scenario.steps()) {
                Map<String, Object> request = new LinkedHashMap<>();
                request.put("operation", step.operation().name());
                request.put("project", step.project());
                // A request for one document names it by project, type and position (the case definition).
                request.put("document", step.document());
                String project = step.project() != null ? step.project()
                        : step.document() != null ? step.document().project() : null;
                request.put("target", project == null ? null
                        : data.assigned(scenario.protagonist(), project) ? LabComposer.Target.ASSIGNED.name()
                        : LabComposer.Target.UNASSIGNED.name());
                request.put("customer", step.customer());
                request.put("items", step.items());
                request.put("claimedTicket", step.claimedTicket());
                request.put("visitorSends", step.sentByVisitor());
                requests.add(request);
            }
            row.put("requests", requests);
            cases.add(row);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("employees", employees);
        body.put("projects", data.projects().values());
        body.put("timeSlots", slots);
        body.put("items", Combination.ITEMS);
        body.put("operations", LabComposer.OPERATIONS.stream().sorted().toList());
        body.put("cases", cases);
        body.put("calls", LabStore.CALLS);
        body.put("assessmentReasons", LabStore.REASONS);
        return ResponseEntity.ok(body);
    }

    /**
     * What the engine received for the same composition in its latest real run from the current template, before the
     * visitor sends it (lab-compare, work 8); the comparison is null when no such run exists.
     */
    @PostMapping("/api/lab/before")
    public ResponseEntity<Object> before(@RequestBody BeforeRequest request) {
        if (request == null || request.caseKey() == null
                || !live.settings().scenarioKeys().contains(request.caseKey())) {
            return ResponseEntity.badRequest().body(Map.of("reason", "UNKNOWN_CASE"));
        }
        try {
            LabComposer.Composed composed = composer.compose(request.caseKey(), request.conditions(), data());
            return ResponseEntity.ok(before.latest(composed.definition(),
                    request.step() == null ? 1 : request.step()));
        } catch (LabComposer.Refused e) {
            return ResponseEntity.badRequest().body(Map.of("reason", e.reason()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("reason", "ENGINE_UNAVAILABLE"));
        }
    }

    @PostMapping("/api/lab/runs")
    public ResponseEntity<Object> start(HttpServletRequest request, @RequestBody StartRequest start) {
        Optional<String> visitor = cookies.visitorOf(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (start == null || start.caseKey() == null || !live.settings().scenarioKeys().contains(start.caseKey())) {
            return ResponseEntity.badRequest().body(Map.of("reason", "UNKNOWN_CASE"));
        }
        LabStore.Prediction prediction = prediction(start.prediction());
        if (start.prediction() != null && prediction == null) {
            return ResponseEntity.badRequest().body(Map.of("reason", "UNKNOWN_CALL"));
        }
        if (live.current(visitor.get()).filter(run -> run.active()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("reason", "RUN_IN_PROGRESS"));
        }
        LabComposer.Composed composed;
        try {
            composed = composer.compose(start.caseKey(), start.conditions(), data());
        } catch (LabComposer.Refused e) {
            return ResponseEntity.badRequest().body(Map.of("reason", e.reason()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("reason", "ENGINE_UNAVAILABLE"));
        }
        Instant composedAt = clock.instant();
        String caseKey = start.caseKey();
        String hash = visitor.get();
        LiveGate.Outcome outcome;
        try {
            outcome = gate.lab(hash, request.getRemoteAddr(), composed.definition(), start.turnstileToken(),
                    summary -> {
                        if (summary.runId() != null) {
                            store.ran(summary.runId(), composed, caseKey, composedAt, hash, prediction);
                        }
                    });
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("reason", "ENGINE_UNAVAILABLE"));
        }
        if (outcome instanceof LiveGate.Started started) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("run", started.run().view());
            body.put("definition", composed.definition());
            body.put("designed", composed.designed());
            body.put("changed", composed.changed());
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(body);
        }
        LiveGate.Refused refused = (LiveGate.Refused) outcome;
        HttpStatus status = switch (refused.reason()) {
            case "VISITOR_LIMIT", "ADDRESS_LIMIT" -> HttpStatus.TOO_MANY_REQUESTS;
            case "ALLOTMENT", "TEMPLATE" -> HttpStatus.SERVICE_UNAVAILABLE;
            case "BUSY" -> HttpStatus.CONFLICT;
            default -> HttpStatus.FORBIDDEN;
        };
        return ResponseEntity.status(status).body(Map.of("reason", refused.reason()));
    }

    @PostMapping("/api/runs/{runId}/steps/{stepNo}/assessment")
    public ResponseEntity<Map<String, String>> assess(HttpServletRequest request, @PathVariable("runId") String runId,
                                                      @PathVariable("stepNo") int stepNo,
                                                      @RequestBody AssessmentRequest body) {
        Optional<String> visitor = cookies.visitorOf(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!RUN_ID.matcher(runId).matches() || stepNo < 1 || body == null
                || !LabStore.VERDICTS.contains(body.verdict())
                || body.reasons() != null && !LabStore.REASONS.containsAll(body.reasons())) {
            return ResponseEntity.badRequest().build();
        }
        LabStore.Assessed result = store.assess(runId, stepNo, visitor.get(), body.verdict(),
                body.reasons() == null ? List.of() : body.reasons());
        return switch (result) {
            case STORED -> ResponseEntity.status(HttpStatus.CREATED).body(Map.of("result", result.name()));
            case NOT_OWNER -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("result", result.name()));
            case DUPLICATE -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("result", result.name()));
            case NO_STEP -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("result", result.name()));
        };
    }

    /**
     * Other visitors' assessments of the same request as the run's step (5A.1 ⑤): same case definition, same
     * measurement setting, same step, counted after the benchmark's delay; the asking visitor's own left out.
     */
    @GetMapping("/api/runs/{runId}/steps/{stepNo}/peer-assessments")
    public ResponseEntity<LabStore.Peers> peers(HttpServletRequest request, @PathVariable("runId") String runId,
                                                @PathVariable("stepNo") int stepNo) {
        if (!RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        return store.peers(runId, stepNo, cookies.visitorOf(request).orElse(null), clock.instant(),
                        BenchmarkService.ASSESSMENT_DELAY_HOURS)
                .map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    /** The visitor's own recent lab runs, newest first (the comparison with the previous run, 5A.1 ④). */
    @GetMapping("/api/lab/runs/recent")
    public ResponseEntity<List<LabStore.RecentRun>> recent(HttpServletRequest request) {
        Optional<String> visitor = cookies.visitorOf(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(store.recent(visitor.get(), 5));
    }

    private LabStore.Prediction prediction(PredictionRequest request) {
        if (request == null) {
            return null;
        }
        if (!LabStore.CALLS.contains(request.call())) {
            return null;
        }
        Map<String, String> approaches = request.approaches() == null ? Map.of() : request.approaches();
        boolean known = approaches.entrySet().stream()
                .allMatch(entry -> List.of("A", "B", "C1", "C2", "D").contains(entry.getKey())
                        && LabStore.APPROACH_CALLS.contains(entry.getValue()));
        return known ? new LabStore.Prediction(request.call(), Map.copyOf(approaches), clock.instant()) : null;
    }

    private synchronized LabData data() throws IOException {
        Instant now = clock.instant();
        if (cachedData == null || !now.isBefore(cachedAt.plus(OPTIONS_CACHE))) {
            cachedData = LabData.of(admin.labOptions());
            cachedAt = now;
        }
        return cachedData;
    }
}
