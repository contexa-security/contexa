package io.contexa.showcase.portal.ops;

import org.springframework.web.bind.annotation.RequestBody;
import java.io.InputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.reactivity.InjectionEvaluator;
import io.contexa.showcase.portal.reactivity.ReactionEvaluator;
import io.contexa.showcase.portal.reactivity.ReactivityRuns;
import io.contexa.showcase.portal.reactivity.ReactivityService;
import io.contexa.showcase.portal.lab.LabStore;
import io.contexa.showcase.portal.lab.LabData;
import io.contexa.showcase.portal.lab.LabComposer;
import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.live.LiveAllotment;
import io.contexa.showcase.portal.live.LiveGateWatch;
import io.contexa.showcase.portal.live.LiveRuns;
import io.contexa.showcase.portal.orchestrator.IsolationSmoke;
import io.contexa.showcase.portal.orchestrator.Measurements;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.orchestrator.RunStore;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.replay.ReplayConsistency;
import io.contexa.showcase.portal.replay.ReplayGuard;
import io.contexa.showcase.portal.replay.ReplayRecorder;
import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.retention.RetentionJob;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.template.CloneVerifier;
import io.contexa.showcase.portal.orchestrator.CleanupRetrier;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateLearner;
import io.contexa.showcase.portal.template.TemplateMaintainer;
import io.contexa.showcase.portal.template.TemplateStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * Operator API of the portal, on the operator port only ({@link OpsPortConfiguration}): learn templates, run
 * scenarios, read results. Jobs run one at a time in the background because a template takes minutes.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class OpsController {

    private static final Logger log = LoggerFactory.getLogger(OpsController.class);

    public record Job(String jobId, String kind, String subject, String status, Instant startedAt, Instant finishedAt,
                      List<Object> results, String error) {
    }

    private final TemplateLearner learner;
    private final TemplateStore templates;
    private final RunOrchestrator orchestrator;
    private final RunStore runs;
    private final ScenarioCatalog scenarios;
    private final WorkloadAdmin admin;
    private final CloneVerifier cloneVerifier;
    private final IsolationSmoke isolationSmoke;
    private final Measurements measurements;
    private final ReplayRecorder recorder;
    private final ReplayStore replays;
    private final ReplayViews replayViews;
    private final ReplayConsistency replayConsistency;
    private final ReplayGuard replayGuard;
    private final ObjectProvider<LiveRuns> liveRuns;
    private final ObjectProvider<LiveAllotment> liveAllotment;
    private final ObjectProvider<LiveGateWatch> liveGateWatch;
    private final RetentionJob retention;
    private final ScoringContract contract;
    private final TemplateCurrency templateCurrency;
    private final ObjectProvider<TemplateMaintainer> templateMaintainer;
    private final CleanupRetrier cleanupRetrier;
    private final LabComposer labComposer;
    private final LabStore labStore;
    /** W6-1: present only with the control D the delivery check reads the sealed prompts of. */
    private final ObjectProvider<ReactivityService> reactivity;
    private final ReactivityRuns reactivityRuns;
    private final ReactionEvaluator reactionVariants;
    private final InjectionEvaluator injectionVariants;
    private final ObjectMapper json;
    /** A harness batch name: letters, digits, dot, dash and underscore. */
    private static final Pattern BATCH = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    /** The visitor mark of the harness's lab runs (W6-1). */
    private static final String HARNESS = "ops-harness";
    private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "showcase-ops-job");
        thread.setDaemon(true);
        return thread;
    });
    private final Map<String, Job> jobs = new ConcurrentHashMap<>();

    public OpsController(TemplateLearner learner, TemplateStore templates, RunOrchestrator orchestrator, RunStore runs,
                         ScenarioCatalog scenarios, WorkloadAdmin admin, CloneVerifier cloneVerifier,
                         IsolationSmoke isolationSmoke, Measurements measurements, ReplayRecorder recorder,
                         ReplayStore replays, ReplayViews replayViews, ReplayConsistency replayConsistency,
                         ReplayGuard replayGuard, ObjectProvider<LiveRuns> liveRuns,
                         ObjectProvider<LiveAllotment> liveAllotment, ObjectProvider<LiveGateWatch> liveGateWatch,
                         RetentionJob retention, ScoringContract contract, TemplateCurrency templateCurrency,
                         ObjectProvider<TemplateMaintainer> templateMaintainer, CleanupRetrier cleanupRetrier,
                         LabComposer labComposer, LabStore labStore, ObjectProvider<ReactivityService> reactivity,
                         ReactivityRuns reactivityRuns, ReactionEvaluator reactionVariants,
                         InjectionEvaluator injectionVariants, ObjectMapper json) {
        this.learner = learner;
        this.templates = templates;
        this.orchestrator = orchestrator;
        this.runs = runs;
        this.scenarios = scenarios;
        this.admin = admin;
        this.cloneVerifier = cloneVerifier;
        this.isolationSmoke = isolationSmoke;
        this.measurements = measurements;
        this.recorder = recorder;
        this.replays = replays;
        this.replayViews = replayViews;
        this.replayConsistency = replayConsistency;
        this.replayGuard = replayGuard;
        this.liveRuns = liveRuns;
        this.liveAllotment = liveAllotment;
        this.liveGateWatch = liveGateWatch;
        this.retention = retention;
        this.contract = contract;
        this.templateCurrency = templateCurrency;
        this.templateMaintainer = templateMaintainer;
        this.cleanupRetrier = cleanupRetrier;
        this.labComposer = labComposer;
        this.labStore = labStore;
        this.reactivity = reactivity;
        this.reactivityRuns = reactivityRuns;
        this.reactionVariants = reactionVariants;
        this.injectionVariants = injectionVariants;
        this.json = json;
    }

    /**
     * W6-1 (P6-CHANGE-2): runs of a case with lab conditions for the harness metrics (plan 8.4, 8.5), on the job queue
     * like the measurement and outside the visitor quotas; the composition is kept like a visitor's lab run. With a
     * batch, every run is recorded under it with its kind (BASE when nothing changed, LAB otherwise, or INJECTION for
     * an injection case run as designed) and its variant label, for the batch metrics of GET /ops/reactivity.
     */
    @PostMapping("/ops/lab-runs")
    public ResponseEntity<Job> labRuns(@RequestParam("caseKey") String caseKey,
                                       @RequestParam(name = "repeat", defaultValue = "1") int repeat,
                                       @RequestParam(name = "batch", required = false) String batch,
                                       @RequestParam(name = "label", required = false) String label,
                                       @RequestParam(name = "kind", required = false) ReactivityRuns.Kind kind,
                                       @RequestBody LabComposer.Conditions conditions) throws IOException {
        if (repeat < 1 || repeat > 10 || scenarios.find(caseKey).isEmpty()
                || (batch != null && !BATCH.matcher(batch).matches()) || kind == ReactivityRuns.Kind.VARIANT
                || (label != null && (label.isBlank() || label.length() > 160))) {
            return ResponseEntity.badRequest().build();
        }
        LabComposer.Composed composed;
        try {
            composed = labComposer.compose(caseKey, conditions, LabData.of(admin.labOptions()));
        } catch (LabComposer.Refused e) {
            return ResponseEntity.badRequest().build();
        }
        ReactivityRuns.Kind recorded = kind != null ? kind
                : composed.designed() ? ReactivityRuns.Kind.BASE : ReactivityRuns.Kind.LAB;
        String runLabel = label != null ? label
                : caseKey + (composed.designed() ? ":designed" : ":" + String.join(",", composed.changed()));
        return ResponseEntity.ok(submit("LAB", caseKey + " " + composed.changed() + " x" + repeat, results -> {
            for (int i = 0; i < repeat; i++) {
                RunOrchestrator.RunSummary summary = orchestrator.run(composed.definition(), null);
                if (summary.runId() != null) {
                    labStore.ran(summary.runId(), composed, caseKey, Instant.now(), HARNESS, null);
                    if (batch != null) {
                        reactivityRuns.record(summary.runId(), batch, recorded, runLabel, caseKey, Instant.now());
                    }
                }
                results.add(summary);
            }
        }));
    }

    /**
     * W6-1: runs of a case-definition variant: of the reaction matrix (plan 8.5, section 4 of the matrix, keys -V) or
     * of the injection places a case definition carries (plan 8.7, keys -I). With a batch, every run is recorded
     * under it with the variant's label.
     */
    @PostMapping("/ops/variant-runs/{variantKey}")
    public ResponseEntity<Job> variantRuns(@PathVariable("variantKey") String variantKey,
                                           @RequestParam(name = "repeat", defaultValue = "1") int repeat,
                                           @RequestParam(name = "batch", required = false) String batch)
            throws IOException {
        if (repeat < 1 || repeat > 10 || !variantKey.matches("[A-Z0-9]+-[VI]\\d+")
                || (batch != null && !BATCH.matcher(batch).matches())) {
            return ResponseEntity.badRequest().build();
        }
        boolean injection = variantKey.matches("[A-Z0-9]+-I\\d+");
        ReactivityRuns.Kind recorded = injection ? ReactivityRuns.Kind.INJECTION : ReactivityRuns.Kind.VARIANT;
        String runLabel = injection
                ? injectionVariants.placeOfKey(variantKey).map(InjectionEvaluator.Place::label).orElse(variantKey)
                : reactionVariants.variantOfKey(variantKey).map(ReactionEvaluator.Variant::label).orElse(variantKey);
        ScenarioDefinition variant;
        try (InputStream stream = OpsController.class.getResourceAsStream("/reactivity/variants/" + variantKey + ".json")) {
            if (stream == null) {
                return ResponseEntity.notFound().build();
            }
            variant = json.readValue(stream, ScenarioDefinition.class);
        }
        return ResponseEntity.ok(submit("VARIANT", variantKey + " x" + repeat, results -> {
            for (int i = 0; i < repeat; i++) {
                RunOrchestrator.RunSummary summary = orchestrator.run(variant, null);
                if (batch != null && summary.runId() != null) {
                    reactivityRuns.record(summary.runId(), batch, recorded, runLabel, variantKey, Instant.now());
                }
                results.add(summary);
            }
        }));
    }

    /** W6-1: the delivery check of a lab condition over the designed run and the run that changed it (plan 8.4). */
    @GetMapping("/ops/reactivity/delivery")
    public ResponseEntity<ReactivityService.RunDelivery> delivery(@RequestParam("base") String baseRunId,
                                                                  @RequestParam("variant") String variantRunId,
                                                                  @RequestParam("condition") String condition,
                                                                  @RequestParam(name = "value", required = false)
                                                                  String value)
            throws IOException {
        ReactivityService service = reactivity.getIfAvailable();
        if (service == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(service.delivery(baseRunId, variantRunId, condition, value));
    }

    /**
     * W6-1: the four harness metrics with their counts and Wilson 95% intervals: delivery, reaction and injection over
     * the runs of a harness batch, invariance over the repetitions of a measurement (plan 8.4 to 8.7).
     */
    @GetMapping("/ops/reactivity")
    public ResponseEntity<ReactivityService.Report> reactivityReport(
            @RequestParam(name = "batch", required = false) String batch,
            @RequestParam(name = "protocol", required = false) String protocol) throws IOException {
        if ((batch == null && protocol == null) || (batch != null && !BATCH.matcher(batch).matches())) {
            return ResponseEntity.badRequest().build();
        }
        ReactivityService service = reactivity.getIfAvailable();
        if (service == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(service.report(batch, protocol));
    }

    /**
     * W6-9 (P6): a release transition of the security decision prompt on control D through its OSS release gate, as
     * the OSS operator API does it (the harness puts the candidate bundle in the shadow release); 422 with the gate's
     * receipt when the gate refuses it.
     */
    @PostMapping("/ops/prompt-releases/transition")
    public ResponseEntity<JsonNode> promptReleaseTransition(@RequestParam("version") String version,
                                                            @RequestParam("target") String target,
                                                            @RequestParam("rationale") String rationale)
            throws IOException {
        if (!version.matches("[0-9A-Za-z.-]{1,64}") || !target.matches("[A-Z_]{1,24}") || rationale.isBlank()
                || rationale.length() > 400) {
            return ResponseEntity.badRequest().build();
        }
        WorkloadAdmin.ReleaseTransition result = admin.promptReleaseTransition(version, target, rationale);
        return ResponseEntity.status(result.status()).body(result.receipt());
    }

    /**
     * W6-9 (P6): what control D keeps for a request, a shadow copy's too: its decisions, analysis events and model
     * calls with their tokens.
     */
    @GetMapping("/ops/engine/decisions/{requestId}")
    public ResponseEntity<JsonNode> engineDecision(@PathVariable("requestId") String requestId) throws IOException {
        if (!requestId.matches("[0-9A-Za-z-]{1,80}")) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(admin.decision(requestId));
    }

    /**
     * W8-3 (P8 rollback rehearsal): a rollback of the security decision prompt's active bundle on control D through
     * its OSS rollback service, as the OSS operator API does it; 422 with the service's refusals.
     */
    @PostMapping("/ops/prompt-releases/rollback")
    public ResponseEntity<JsonNode> promptRollback(@RequestParam("from") String from, @RequestParam("to") String to,
                                                   @RequestParam("reason") String reason,
                                                   @RequestParam(name = "emergency", defaultValue = "false")
                                                   boolean emergency) throws IOException {
        if (!from.matches("[0-9A-Za-z.-]{1,64}") || !to.matches("[0-9A-Za-z.-]{1,64}") || reason.isBlank()
                || reason.length() > 400) {
            return ResponseEntity.badRequest().build();
        }
        WorkloadAdmin.ReleaseTransition result = admin.promptRollback(from, to, reason, emergency);
        return ResponseEntity.status(result.status()).body(result.receipt());
    }

    /**
     * W8-3 (W6-8 design: the harness records the evaluation after a measurement): an evaluation of a bundle on
     * control D with its bundle hash and run reference, the release gate's evidence of that bundle only.
     */
    @PostMapping("/ops/prompt-releases/evaluation")
    public ResponseEntity<JsonNode> promptEvaluation(@RequestBody JsonNode evaluation) throws IOException {
        WorkloadAdmin.ReleaseTransition result = admin.promptEvaluation(evaluation);
        return ResponseEntity.status(result.status()).body(result.receipt());
    }

    /** W8-3: the approval of a rollback that waits for one (an emergency stop is approved afterwards). */
    @PostMapping("/ops/prompt-releases/rollback/{executionKey}/approve")
    public ResponseEntity<JsonNode> promptRollbackApproval(@PathVariable("executionKey") String executionKey)
            throws IOException {
        if (!executionKey.matches("[0-9A-Za-z_-]{1,80}")) {
            return ResponseEntity.badRequest().build();
        }
        WorkloadAdmin.ReleaseTransition result = admin.promptRollbackApproval(executionKey);
        return ResponseEntity.status(result.status()).body(result.receipt());
    }

    /**
     * The R1 scoring contract draft and its version, for the operator only: the benchmark is not part of the first
     * release (ADR-28), so the draft is not served to visitors.
     */
    @GetMapping("/ops/contract")
    public Map<String, Object> contract() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractVersion", contract.version());
        body.put("status", contract.status());
        body.put("contract", contract.document());
        return body;
    }

    /** P5-PRV-02: the latest retention passes and what each step deleted. */
    @GetMapping("/ops/retention")
    public List<Map<String, Object>> retention() {
        return retention.recent(20);
    }

    /** Runs a retention pass now (it also runs daily at 03:30 UTC). */
    @PostMapping("/ops/retention/run")
    public RetentionJob.Pass runRetention() {
        return retention.run();
    }

    /** P2 recording harness: every scene of the pair runs the given number of times on fresh principals. */
    @PostMapping("/ops/recordings/{pairKey}")
    public Job record(@PathVariable("pairKey") String pairKey,
                      @RequestParam(name = "repetitions", defaultValue = "5") int repetitions) {
        return submit("RECORDING", pairKey + " x" + repetitions,
                results -> results.addAll(recorder.record(pairKey, repetitions)));
    }

    /** Records a pair from the runs of a measurement protocol, without new runs (work 6); drafts until published. */
    @PostMapping("/ops/recordings/{pairKey}/from-measurement")
    public List<ReplayRecorder.SceneResult> recordFromMeasurement(@PathVariable("pairKey") String pairKey,
                                                                  @RequestParam("protocol") String protocolId) {
        return recorder.recordFromMeasurement(pairKey, protocolId);
    }

    @GetMapping("/ops/recordings")
    public List<ReplayStore.RecordRow> recordings() {
        return replays.list();
    }

    @GetMapping("/ops/recordings/{recordId}/preview")
    public ResponseEntity<ReplayView.Scene> preview(@PathVariable("recordId") String recordId) {
        return replayViews.preview(recordId).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** P2-BE-01 with the engine: specification fields and hash, runs, agreement and the original decision records. */
    @GetMapping("/ops/recordings/check")
    public List<ReplayConsistency.Finding> checkRecordings() throws IOException {
        List<ReplayConsistency.Finding> findings = replayConsistency.check(this::engineRecord);
        replayGuard.apply(findings);
        return findings;
    }

    /** Publishes a recording after it passes the consistency check with the engine. */
    @PostMapping("/ops/recordings/{recordId}/publish")
    public ResponseEntity<ReplayConsistency.Finding> publish(@PathVariable("recordId") String recordId)
            throws IOException {
        Optional<ReplayStore.RecordRow> record = replays.find(recordId);
        if (record.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        ReplayConsistency.Finding finding = replayConsistency.check(record.get(), this::engineRecord);
        if (!finding.consistent() || !replays.publish(recordId)) {
            return ResponseEntity.status(409).body(finding);
        }
        return ResponseEntity.ok(finding);
    }

    private Optional<JsonNode> engineRecord(String requestId) throws IOException {
        JsonNode records = admin.decision(requestId).path("records");
        return records.isArray() && !records.isEmpty() ? Optional.of(records.get(0)) : Optional.empty();
    }

    /** P1-OPS-01: model usage, analysis time, unresolved share and cost since the given time. */
    @GetMapping("/ops/measurements")
    public Map<String, Object> measurements(@RequestParam(name = "since", defaultValue = "1970-01-01T00:00:00Z")
                                            String since) {
        return measurements.since(Instant.parse(since));
    }

    /** P1-BE-09: isolation smoke tests T1 to T7 on the real engine (about 15 runs). */
    @PostMapping("/ops/isolation-smoke")
    public Job isolationSmoke() {
        return submit("ISOLATION_SMOKE", "T1-T7", results -> results.add(isolationSmoke.run()));
    }

    @PostMapping("/ops/templates/{employeeKey}/learn")
    public Job learn(@PathVariable("employeeKey") String employeeKey) {
        return submit("TEMPLATE", employeeKey, results -> results.add(Map.of("templateId",
                String.valueOf(learner.learn(employeeKey)))));
    }

    /** P1-BE-06: clone the READY template into fresh principals and compare each clone with the template. */
    @PostMapping("/ops/templates/{employeeKey}/clone-check")
    public Job cloneCheck(@PathVariable("employeeKey") String employeeKey,
                          @RequestParam(name = "count", defaultValue = "10") int count) {
        return submit("CLONE_CHECK", employeeKey + " x" + count,
                results -> results.addAll(cloneVerifier.verify(employeeKey, count)));
    }

    @GetMapping("/ops/templates")
    public List<Map<String, Object>> templates() {
        return templates.list();
    }

    /**
     * The versions in force, each protagonist's current template (learned under them, the only kind runs clone) and
     * the automatic re-learning's last check when it is on (N-8).
     */
    @GetMapping("/ops/templates/current")
    public Map<String, Object> currentTemplates() throws IOException {
        Map<String, Object> current = new LinkedHashMap<>();
        current.put("versionKey", templateCurrency.currentKey());
        Map<String, Object> employees = new LinkedHashMap<>();
        TreeSet<String> protagonists = new TreeSet<>(admin.protagonists());
        scenarios.all().stream().filter(ScenarioDefinition::template).map(ScenarioDefinition::protagonist)
                .forEach(protagonists::add);
        protagonists.forEach(employee -> employees.put(employee, templateCurrency.currentOrFail(employee)
                .map(TemplateStore.ReadyTemplate::templateId).orElse(null)));
        current.put("templates", employees);
        TemplateMaintainer maintainer = templateMaintainer.getIfAvailable();
        current.put("autoLearn", maintainer != null);
        current.put("lastCheck", maintainer == null ? null : maintainer.last());
        return current;
    }

    /** Runs one pass of the clean-up retry now (it also runs every five minutes, N-6). */
    @PostMapping("/ops/cleanup/retry")
    public CleanupRetrier.Pass retryCleanups() {
        return cleanupRetrier.run();
    }

    @GetMapping("/ops/templates/{templateId}/steps")
    public List<Map<String, Object>> templateSteps(@PathVariable("templateId") String templateId) {
        return templates.steps(templateId);
    }

    @GetMapping("/ops/scenarios")
    public List<ScenarioDefinition> scenarios() {
        return List.copyOf(scenarios.all());
    }

    @PostMapping("/ops/runs/{scenarioKey}")
    public ResponseEntity<Job> run(@PathVariable("scenarioKey") String scenarioKey,
                                   @RequestParam(name = "repeat", defaultValue = "1") int repeat,
                                   @RequestParam(name = "forcedAction", required = false) String forcedAction) {
        ScenarioDefinition scenario = scenarios.find(scenarioKey).orElse(null);
        if (scenario == null || repeat < 1 || repeat > 100
                || (forcedAction != null && !"CHALLENGE".equals(forcedAction))) {
            return ResponseEntity.badRequest().build();
        }
        String subject = scenarioKey + " x" + repeat + (forcedAction == null ? "" : " forced " + forcedAction);
        return ResponseEntity.ok(submit("RUN", subject, results -> {
            for (int i = 0; i < repeat; i++) {
                results.add(orchestrator.run(scenario, forcedAction));
            }
        }));
    }

    /**
     * The measurement protocol (docs/showcase/데모-재설계.md W5-0, R-14): every designed case of the catalog (or the
     * listed ones), {@code repeat} times, one after another under the engine setting in force. Its runs are the only
     * source of the benchmark's scores; a forced decision is never allowed here.
     */
    @PostMapping("/ops/protocol")
    public ResponseEntity<Job> protocol(@RequestParam(name = "repeat", defaultValue = "5") int repeat,
                                        @RequestParam(name = "cases", required = false) List<String> cases) {
        List<ScenarioDefinition> selected = cases == null || cases.isEmpty() ? List.copyOf(scenarios.all())
                : cases.stream().map(key -> scenarios.find(key).orElse(null)).toList();
        // An immutable list refuses contains(null), so an unknown case is looked for element by element.
        if (repeat < 1 || repeat > 50 || selected.stream().anyMatch(Objects::isNull)) {
            return ResponseEntity.badRequest().build();
        }
        String protocolId = "protocol-" + UUID.randomUUID().toString().substring(0, 8);
        runs.protocolStarted(protocolId, repeat, selected.stream().map(ScenarioDefinition::key).toList());
        return ResponseEntity.ok(submit("PROTOCOL", protocolId + " x" + repeat, results -> {
            try {
                for (int i = 0; i < repeat; i++) {
                    for (ScenarioDefinition scenario : selected) {
                        RunOrchestrator.RunSummary summary = orchestrator.run(scenario, null);
                        if (summary.runId() != null) {
                            runs.protocolRun(protocolId, summary.runId());
                        }
                        results.add(summary);
                    }
                }
            } finally {
                runs.protocolFinished(protocolId);
            }
        }));
    }

    @GetMapping("/ops/jobs/{jobId}")
    public ResponseEntity<Job> job(@PathVariable("jobId") String jobId) {
        Job job = jobs.get(jobId);
        return job == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(job);
    }

    @GetMapping("/ops/jobs")
    public List<Job> jobs() {
        return new ArrayList<>(jobs.values());
    }

    @GetMapping("/ops/runs/{runId}")
    public ResponseEntity<Map<String, Object>> runResult(@PathVariable("runId") String runId) {
        Map<String, Object> run = runs.run(runId);
        return run.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(run);
    }

    /**
     * P5-SEC-07: spaces and queue, the daily allotment and the gate's outcomes by reason; 404 while live runs are
     * off.
     */
    @GetMapping("/ops/live/status")
    public ResponseEntity<Map<String, Object>> liveStatus() {
        LiveRuns live = liveRuns.getIfAvailable();
        LiveAllotment allotment = liveAllotment.getIfAvailable();
        LiveGateWatch watch = liveGateWatch.getIfAvailable();
        if (live == null || allotment == null || watch == null) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> spaces = new LinkedHashMap<>();
        spaces.put("running", live.running());
        spaces.put("waiting", live.waiting());
        spaces.put("spaces", live.spaces());
        spaces.put("maxConcurrent", live.settings().maxConcurrent());
        spaces.put("maxQueue", live.settings().maxQueue());
        spaces.put("startsPerMinute", live.settings().startsPerMinute());
        spaces.put("startsInLastMinute", live.startsInLastMinute());
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("spaces", spaces);
        status.put("allotment", allotment.state());
        status.put("gate", watch.status());
        return ResponseEntity.ok(status);
    }

    @GetMapping("/ops/engine")
    public Map<String, Object> engine() throws IOException {
        Map<String, Object> engine = new LinkedHashMap<>();
        engine.put("engine", admin.engine());
        engine.put("company", admin.company());
        return engine;
    }

    @FunctionalInterface
    interface Work {
        void run(List<Object> results) throws Exception;
    }

    private Job submit(String kind, String subject, Work work) {
        String jobId = UUID.randomUUID().toString();
        List<Object> results = Collections.synchronizedList(new ArrayList<>());
        jobs.put(jobId, new Job(jobId, kind, subject, "QUEUED", Instant.now(), null, results, null));
        executor.submit(() -> {
            jobs.computeIfPresent(jobId, (id, job) -> new Job(id, kind, subject, "RUNNING", job.startedAt(), null,
                    results, null));
            String status = "DONE";
            String error = null;
            try {
                work.run(results);
            } catch (Exception e) {
                log.error("Operator job failed: jobId={}, kind={}, subject={}", jobId, kind, subject, e);
                status = "FAILED";
                error = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            String finalStatus = status;
            String finalError = error;
            jobs.computeIfPresent(jobId, (id, job) -> new Job(id, kind, subject, finalStatus, job.startedAt(),
                    Instant.now(), results, finalError));
        });
        return jobs.get(jobId);
    }
}
