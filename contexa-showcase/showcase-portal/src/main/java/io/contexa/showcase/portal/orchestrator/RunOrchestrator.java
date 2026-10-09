package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.anatomy.AnatomyStore;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.spec.ExecutionSpec;
import io.contexa.showcase.portal.spec.ExecutionSpecHasher;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Fact;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Step;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
import io.contexa.showcase.portal.template.TemplateVersions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Orchestrator v0 (plan 3.3): one run is one fresh principal. It clones the protagonist's template into the engine,
 * creates the plain accounts and the run's company facts, signs in to all five controls, sends every step to each
 * control in the same order, collects the four evidence links (engine decision, time of application, HTTP response,
 * business outcome) and removes everything the run created.
 */
public class RunOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(RunOrchestrator.class);

    private final AnatomyStore anatomies;

    /** How long a refused step of control D is watched for a decision record before it counts as an earlier one's. */
    static final Duration REFUSED_DECISION_WAIT = Duration.ofSeconds(5);
    /** Longest wait after the first decision record for the engine's closing event (R-22). */
    static final Duration DECISION_SETTLE_WAIT = Duration.ofSeconds(5);
    /** How long to look for a decision record of a re-issued request (async analysis takes a few seconds). */
    static final Duration REISSUE_DECISION_WAIT = Duration.ofSeconds(10);

    private final ControlEndpoints endpoints;
    private final WorkloadAdmin admin;
    private final InternalContextSigner signer;
    private final RunStore store;
    private final TemplateCurrency templates;
    private final ExecutionSpecStore specs;
    private final ScoringContract contract;
    private final ObjectMapper json;
    private final SecureRandom random = new SecureRandom();

    public RunOrchestrator(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                           RunStore store, TemplateCurrency templates, ExecutionSpecStore specs, ScoringContract contract,
                           ObjectMapper json) {
        this(endpoints, admin, signer, store, templates, specs, contract, json, null);
    }

    /**
     * @param anatomies builds and stores the verdict anatomy of every step when a run ends (W1-4b); null leaves it to
     *                  the first visitor request
     */
    public RunOrchestrator(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                           RunStore store, TemplateCurrency templates, ExecutionSpecStore specs, ScoringContract contract,
                           ObjectMapper json, AnatomyStore anatomies) {
        this.anatomies = anatomies;
        this.endpoints = endpoints;
        this.admin = admin;
        this.signer = signer;
        this.store = store;
        this.templates = templates;
        this.specs = specs;
        this.contract = contract;
        this.json = json;
    }

    public record RunSummary(String runId, String scenarioKey, String principal, String organization,
                             String status, String failure, List<StepSummary> steps) {
    }

    /**
     * @param challenge the additional check of control D's step, null when the engine asked none
     */
    public record StepSummary(int stepNo, String operation, String path, Map<String, String> outcomes,
                              Map<String, String> expected, boolean rulesAsExpected, String engineAction,
                              String applied, boolean unresolved, String requestId, String promptSha256,
                              List<String> foreignPrincipals, ChallengeSummary challenge) {
    }

    /** Milliseconds are counted from the moment the challenge answer came back. */
    public record ChallengeSummary(boolean answered, String reason, Long codeRequestedMs, Long verifiedMs,
                                   Long reissueSentMs, Integer reissueStatus, String reissueOutcome,
                                   Boolean reissueReanalysed) {
    }

    public RunSummary run(ScenarioDefinition scenario) {
        return run(scenario, null);
    }

    /** True when control D accepts development-only forced decisions; replays are never recorded then. */
    public boolean engineAcceptsForcedDecisions() throws IOException {
        return admin.engine().path("forcedActions").asBoolean(false);
    }

    /**
     * @param forcedAction development-only decision forced on control D before each step (operator check of the
     *                     challenge flow); the run is marked and can never be recorded or published
     */
    public RunSummary run(ScenarioDefinition scenario, String forcedAction) {
        return run(scenario, forcedAction, ChallengeResponder.AUTOMATIC, RunListener.NONE);
    }

    /**
     * @param responder answers control D's additional checks: automatically for recordings, by the visitor live
     * @param listener  hears each control's result as it arrives
     */
    public RunSummary run(ScenarioDefinition scenario, String forcedAction, ChallengeResponder responder,
                          RunListener listener) {
        String runHex = HexFormat.of().formatHex(randomBytes(6));
        String runId = "run-" + runHex;
        String username = "v" + runHex + "-" + scenario.protagonist();
        String password = "Run-" + UUID.randomUUID() + "-Aa1";
        List<StepSummary> summaries = new ArrayList<>();
        Map<String, Object> cleanup = new LinkedHashMap<>();
        String status = "COMPLETED";
        String failure = null;
        boolean started = false;
        String organization = "org-" + runHex;
        RunApprover approver = null;
        try {
            JsonNode company = admin.company();
            LocalDate anchor = LocalDate.parse(company.path("anchorDate").asText());
            JsonNode employee = admin.employee(scenario.protagonist());
            Instant companyTime = CompanyCalendar.at(anchor, scenario.timeSlot());
            String device = scenario.device() == ScenarioDefinition.Device.NEW ? CompanyBlueprint.NEW_DEVICE
                    : employee.path("usualDevice").asText();
            RunIdentity run = new RunIdentity(runId, "org-" + runHex, "tenant-" + runHex,
                    hostIn(network(scenario, employee.path("officeNetwork").asText()), 30 + random.nextInt(220)),
                    device);
            Map<String, Long> stages = new LinkedHashMap<>();
            long stageStart = System.nanoTime();
            Optional<TemplateStore.ReadyTemplate> template = scenario.template()
                    ? templates.current(scenario.protagonist()) : Optional.empty();
            stageStart = stage(stages, "template", stageStart);
            if (scenario.template() && template.isEmpty()) {
                throw new IllegalStateException("No template of " + scenario.protagonist()
                        + " learned under the versions in force");
            }
            String definition = canonicalJson(json.valueToTree(scenario));
            store.start(new RunStore.RunStart(runId, scenario.key(), scenario.version(), scenario.protagonist(),
                    username, template.map(TemplateStore.ReadyTemplate::templateId).orElse(null), run.organization(),
                    run.tenant(), run.clientIp(), run.device(), companyTime, forcedAction, listener.liveVisitor(),
                    definition, RunStore.sha256(definition)));
            started = true;
            listener.runStarted(runId);

            admin.registerPlainPrincipal(run, username, password, scenario.protagonist());
            RunFacts facts = facts(scenario, runHex, companyTime);
            if (!facts.equals(RunFacts.none())) {
                admin.addFacts(run, facts);
            }
            stageStart = stage(stages, "businessPrincipal", stageStart);
            Map<String, Object> principal = new LinkedHashMap<>();
            principal.put("username", username);
            principal.put("password", password);
            principal.put("employeeKey", scenario.protagonist());
            principal.put("roleKey", employee.path("roleKey").asText());
            principal.put("displayName", employee.path("displayName").asText());
            principal.put("department", employee.path("department").asText());
            principal.put("organizationId", run.organization());
            principal.put("tenantId", run.tenant());
            principal.put("template", template.map(TemplateStore.ReadyTemplate::snapshot).orElse(null));
            admin.createEnginePrincipal(run, principal);
            stageStart = stage(stages, "enginePrincipal", stageStart);

            String templateId = template.map(TemplateStore.ReadyTemplate::templateId).orElse(null);
            List<String> systemPromptHashes = new ArrayList<>();
            Map<Control, ControlSession> sessions = new EnumMap<>(Control.class);
            Instant signInTime = companyTime.minus(Duration.ofMinutes(2));
            for (Control control : Control.values()) {
                ControlSession session = new ControlSession(control,
                        new WorkloadClient(endpoints.of(control), signer, run, endpoints.requestTimeout()), json);
                if (control.plain()) {
                    session.signInPlain(username, password, signInTime);
                } else {
                    stageStart = stage(stages, "plainSignIn", stageStart);
                    session.signInEngine(username, password, username + "@" + CompanyBlueprint.EMAIL_DOMAIN,
                            signInTime, admin);
                    stage(stages, "engineSignIn", stageStart);
                }
                sessions.put(control, session);
            }
            listener.principalReady(stages);
            approver = new RunApprover(admin, run, runHex, companyTime, () -> new ControlSession(Control.D,
                    new WorkloadClient(endpoints.of(Control.D), signer, run, endpoints.requestTimeout()), json));

            for (int index = 0; index < scenario.steps().size(); index++) {
                Step step = scenario.steps().get(index);
                int stepNo = index + 1;
                if (step.sentByVisitor() && !listener.awaitVisitor(stepNo)) {
                    break;
                }
                String path = path(step, runHex);
                Instant stepTime = companyTime.plusSeconds(step.offsetSeconds());
                Map<Control, ControlResult> results = dispatch(new StepCall(runId, username, scenario, step, stepNo,
                        path, stepTime, forcedAction, responder, listener, approver), sessions);
                Map<String, String> outcomes = new LinkedHashMap<>();
                for (Control control : Control.values()) {
                    outcomes.put(control.name(), results.get(control).outcome().outcome());
                }
                StepOutcome engineOutcome = results.get(Control.D).outcome();
                ControlSession.ChallengeTrace challenge = results.get(Control.D).challenge();
                EngineDecision decision = engineDecision(step, engineOutcome);
                store.decision(runId, stepNo, engineOutcome.requestId(), decision);
                collectExchanges(runId, stepNo, engineOutcome.requestId());
                ControlSession.ReleaseTrace release = results.get(Control.D).release();
                if (release != null) {
                    store.release(runId, stepNo, engineOutcome.requestId(), release);
                }
                ChallengeSummary challengeSummary = null;
                if (challenge != null) {
                    Boolean reanalysed = challenge.reissue() == null ? null : reanalysed(challenge.reissue());
                    store.challenge(runId, stepNo, engineOutcome.requestId(), challenge, reanalysed);
                    challengeSummary = summary(challenge, reanalysed);
                }
                for (JsonNode call : decision.raw().path("modelCalls")) {
                    store.cost(runId, null, engineOutcome.requestId(), call);
                    if (call.hasNonNull("systemPromptSha256")) {
                        systemPromptHashes.add(call.path("systemPromptSha256").asText());
                    }
                }
                summaries.add(new StepSummary(stepNo, step.operation().name(), path, outcomes, step.expected(),
                        rulesAsExpected(step.expected(), outcomes), decision.finalAction(), decision.applied(),
                        decision.unresolved(), engineOutcome.requestId(), firstPromptSha(decision),
                        foreignPrincipals(decision, username), challengeSummary));
                // In a live run a step the visitor sends goes when the visitor presses, not after the pacing wait.
                if (scenario.pace() == ScenarioDefinition.Pace.PACED && index < scenario.steps().size() - 1
                        && !(scenario.steps().get(index + 1).sentByVisitor() && listener.liveVisitor() != null)) {
                    sleep(endpoints.allowWindow());
                }
            }
            for (StepSummary summary : summaries) {
                collectExchanges(runId, summary.stepNo(), summary.requestId());
            }
            if (template.isPresent()) {
                try {
                    JsonNode atEnd = admin.snapshot(username, scenario.protagonist(), run.organization(),
                            run.tenant());
                    store.learning(runId, template.get().templateId(), RunLearning.summary(json,
                            template.get().templateId(), template.get().snapshot(), atEnd));
                } catch (IOException | RuntimeException e) {
                    log.error("Run learning could not be read: runId={}", runId, e);
                }
            }
            if (anatomies != null) {
                try {
                    anatomies.buildAll(runId);
                } catch (RuntimeException e) {
                    log.error("Verdict anatomies could not be built: runId={}", runId, e);
                }
            }
            store.businessEvidence(runId, admin.plainEvidence(runId));
            // A run with no model call still has a specification (H-22): the permission check or an earlier
            // decision refused it before any analysis, under the same engine, rules and templates.
            JsonNode engine = admin.engine();
            ExecutionSpec spec = ExecutionSpecStore.build(engine, admin.rules(), templateId,
                    systemPromptHashes.isEmpty() ? ExecutionSpec.NO_MODEL_CALL : systemPromptHashes.get(0),
                    contract.version());
            store.spec(runId, specs.record(spec),
                    ExecutionSpecHasher.settingHash(spec, TemplateVersions.key(engine, admin.company())));
            for (JsonNode call : admin.embeddings(username)) {
                store.cost(runId, null, null, call);
            }
        } catch (IOException | RuntimeException e) {
            log.error("Run failed: runId={}, scenario={}", runId, scenario.key(), e);
            status = "FAILED";
            failure = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            cleanup.putAll(cleanup(runId, username));
            if (approver != null && approver.created()) {
                try {
                    cleanup.put("approver", admin.deleteEnginePrincipal(runId, approver.username()));
                } catch (IOException | RuntimeException e) {
                    log.error("Approver cleanup failed: runId={}", runId, e);
                    cleanup.put("approverError", e.getMessage());
                }
            }
            if (started) {
                store.finish(runId, status, failure, cleanup);
            }
        }
        return new RunSummary(runId, scenario.key(), username, organization, status, failure, summaries);
    }

    /** One step of a run as every control receives it. */
    private record StepCall(String runId, String username, ScenarioDefinition scenario, Step step, int stepNo,
                            String path, Instant stepTime, String forcedAction, ChallengeResponder responder,
                            RunListener listener, Approver approver) {
    }

    /** A control's answer to a step and, for control D, how its additional check or the release of a block ended. */
    private record ControlResult(StepOutcome outcome, ControlSession.ChallengeTrace challenge,
                                 ControlSession.ReleaseTrace release) {
    }

    /**
     * Sends the same request of a step to every control at once, so a visitor sees the five answers arrive side by
     * side and a stream runs at every control in the same seconds. Each control has its own session; control D also
     * waits for its additional check in its own task, while the other controls finish.
     */
    private Map<Control, ControlResult> dispatch(StepCall call, Map<Control, ControlSession> sessions)
            throws IOException {
        ExecutorService pool = Executors.newFixedThreadPool(Control.values().length, task -> {
            Thread thread = new Thread(task, "run-step-" + call.runId());
            thread.setDaemon(true);
            return thread;
        });
        try {
            Map<Control, Future<ControlResult>> futures = new EnumMap<>(Control.class);
            for (Control control : Control.values()) {
                futures.put(control, pool.submit(() -> sendOne(call, control, sessions.get(control))));
            }
            Map<Control, ControlResult> results = new EnumMap<>(Control.class);
            for (Map.Entry<Control, Future<ControlResult>> entry : futures.entrySet()) {
                results.put(entry.getKey(), await(entry.getValue()));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private ControlResult sendOne(StepCall call, Control control, ControlSession session) throws IOException {
        if (control == Control.D && call.forcedAction() != null) {
            admin.forceAction(call.username(), call.forcedAction());
        }
        RunListener listener = call.listener();
        StepOutcome outcome = session.send(call.step().operation(), call.path(), call.stepTime(),
                new ControlSession.SendListener() {
                    @Override
                    public void sent(String requestId, Instant sentAt) {
                        listener.requestSent(call.stepNo(), control, call.step().operation(), requestId, sentAt);
                    }

                    @Override
                    public void streamProgress(Integer total, long atMs, int delivered) {
                        listener.streamProgress(call.stepNo(), control, total, atMs, delivered);
                    }
                });
        store.armResult(call.runId(), call.stepNo(), control, call.step().operation().name(), outcome);
        listener.stepResult(call.stepNo(), call.step().operation().name(), control, outcome);
        ControlSession.ChallengeTrace challenge = null;
        ControlSession.ReleaseTrace release = null;
        String email = call.username() + "@" + CompanyBlueprint.EMAIL_DOMAIN;
        if (control == Control.D && ControlSession.challenged(outcome)) {
            challenge = call.responder().respond(new ChallengeResponder.Challenge(
                    call.scenario().oracle().classification(),
                    outcome.sentAt().plusMillis(outcome.elapsedMs()),
                    session.challengeActions(call.username(), email, call.step().operation(), call.path(),
                            call.stepTime(), admin)));
        } else if (control == Control.D && ControlSession.blocked(outcome)) {
            release = call.responder().release(new ChallengeResponder.Release(
                    call.scenario().oracle().classification(),
                    outcome.sentAt().plusMillis(outcome.elapsedMs()), call.username(),
                    session.releaseActions(call.username(), email, call.step().operation(), call.path(),
                            call.stepTime(), admin),
                    call.approver()));
        }
        return new ControlResult(outcome, challenge, release);
    }

    private static ControlResult await(Future<ControlResult> future) throws IOException {
        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while a control answered", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {
                throw io;
            }
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IOException(cause);
        }
    }

    /**
     * Control D's decision for a step. A synchronous step has its record before the response; an asynchronous one
     * gets it shortly after. A step the engine refused because of an earlier decision gets no record of its own.
     */
    private EngineDecision engineDecision(Step step, StepOutcome outcome) throws IOException {
        if (step.operation() == BusinessOperation.PROJECT_LIST) {
            return EngineDecision.none(json.createObjectNode());
        }
        boolean synchronous = EngineDecision.synchronous(step.operation());
        Duration wait = "REFUSED".equals(outcome.outcome()) && !synchronous ? REFUSED_DECISION_WAIT
                : endpoints.decisionWait();
        Instant deadline = Instant.now().plus(wait);
        Instant settleBy = null;
        JsonNode evidence;
        do {
            evidence = admin.decision(outcome.requestId());
            EngineDecision decision = EngineDecision.from(evidence, synchronous);
            if (decision != null) {
                // A record can appear before the engine closes the analysis (a retry still running); the decision
                // is taken once the engine announced it applied or failed, or after a short settle wait (R-22).
                if (settleBy == null) {
                    settleBy = Instant.now().plus(DECISION_SETTLE_WAIT);
                }
                if (closed(evidence) || !Instant.now().isBefore(settleBy)) {
                    return decision;
                }
            }
            sleep(Duration.ofSeconds(1));
        } while (Instant.now().isBefore(deadline) || settleBy != null && Instant.now().isBefore(settleBy));
        EngineDecision late = EngineDecision.from(evidence, synchronous);
        return late != null ? late : EngineDecision.none(evidence);
    }

    /** The engine announced the end of the analysis: the decision was applied or the analysis failed. */
    static boolean closed(JsonNode evidence) {
        for (JsonNode event : evidence.path("events")) {
            String type = event.path("type").asText();
            if ("DECISION_APPLIED".equals(type) || "ANALYSIS_ERROR".equals(type)) {
                return true;
            }
        }
        return false;
    }

    /** Stores the model calls control D kept for a decision; a failure is logged and never fails the run. */
    private void collectExchanges(String runId, int stepNo, String requestId) {
        if (requestId == null) {
            return;
        }
        try {
            store.exchanges(runId, stepNo, requestId, admin.exchanges(requestId));
        } catch (IOException | RuntimeException e) {
            log.error("Model exchanges could not be collected: runId={}, step={}", runId, stepNo, e);
        }
    }

    /** The SHA-256 a run stores for its definition (run.scenario_sha256), so runs of the same definition are found. */
    public static String definitionSha256(ObjectMapper json, ScenarioDefinition scenario) {
        return RunStore.sha256(canonicalJson(json.valueToTree(scenario)));
    }

    /** JSON with object keys sorted at every level, so the same definition always has the same hash. */
    static String canonicalJson(JsonNode node) {
        return sorted(node).toString();
    }

    private static JsonNode sorted(JsonNode node) {
        if (node.isObject()) {
            ObjectNode copy = JsonNodeFactory.instance.objectNode();
            List<String> names = new ArrayList<>();
            node.fieldNames().forEachRemaining(names::add);
            names.sort(null);
            for (String name : names) {
                copy.set(name, sorted(node.get(name)));
            }
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> copy.add(sorted(element)));
            return copy;
        }
        return node;
    }

    /**
     * Whether the engine analysed the re-issued request again: it has a decision record of its own within the wait.
     * After a completed check the engine binds an ALLOW to the rotated session (core F-2), so none is expected.
     */
    private boolean reanalysed(StepOutcome reissue) throws IOException {
        Instant deadline = Instant.now().plus(REISSUE_DECISION_WAIT);
        do {
            if (EngineDecision.from(admin.decision(reissue.requestId()), false) != null) {
                return true;
            }
            sleep(Duration.ofSeconds(1));
        } while (Instant.now().isBefore(deadline));
        return false;
    }

    static ChallengeSummary summary(ControlSession.ChallengeTrace trace, Boolean reanalysed) {
        StepOutcome reissue = trace.reissue();
        return new ChallengeSummary(trace.answered(), trace.reason(), since(trace.challengedAt(),
                trace.codeRequestedAt()), since(trace.challengedAt(), trace.verifiedAt()),
                reissue == null ? null : since(trace.challengedAt(), reissue.sentAt()),
                reissue == null ? null : reissue.httpStatus(), reissue == null ? null : reissue.outcome(), reanalysed);
    }

    private static Long since(Instant from, Instant to) {
        return to == null ? null : Duration.between(from, to).toMillis();
    }

    /** Records the stage that started at {@code start} and returns the start of the next one. */
    private static long stage(Map<String, Long> stages, String name, long start) {
        long now = System.nanoTime();
        stages.put(name, (now - start) / 1_000_000L);
        return now;
    }

    /** Hash of the normalised prompt of the step's first model call (isolation tests T6, T7). */
    static String firstPromptSha(EngineDecision decision) {
        for (JsonNode call : decision.raw().path("modelCalls")) {
            if (call.hasNonNull("promptSha256")) {
                return call.path("promptSha256").asText();
            }
        }
        return null;
    }

    /** Run principals other than the run's own that appear in the step's prompts (isolation test T5). */
    static List<String> foreignPrincipals(EngineDecision decision, String username) {
        List<String> foreign = new ArrayList<>();
        for (JsonNode call : decision.raw().path("modelCalls")) {
            for (JsonNode principal : call.path("promptPrincipals")) {
                if (!principal.asText().equals(username) && !foreign.contains(principal.asText())) {
                    foreign.add(principal.asText());
                }
            }
        }
        return foreign;
    }

    private Map<String, Object> cleanup(String runId, String username) {
        Map<String, Object> cleanup = new LinkedHashMap<>();
        try {
            cleanup.put("engine", admin.deleteEnginePrincipal(runId, username));
        } catch (IOException | RuntimeException e) {
            log.error("Engine cleanup failed: runId={}", runId, e);
            cleanup.put("engineError", e.getMessage());
        }
        try {
            cleanup.put("business", admin.deletePlainRun(runId));
        } catch (IOException | RuntimeException e) {
            log.error("Business cleanup failed: runId={}", runId, e);
            cleanup.put("businessError", e.getMessage());
        }
        return cleanup;
    }

    private String path(Step step, String runHex) throws IOException {
        return switch (step.operation()) {
            case PROJECT_LIST -> "/api/projects";
            case DOCUMENT_READ -> "/api/documents/" + document(step, runHex);
            case DOCUMENT_DOWNLOAD -> "/api/documents/" + document(step, runHex) + "/download";
            case EXPORT -> "/api/projects/" + step.project() + "/exports?items=" + step.items() + claim(step, runHex);
            case EXPORT_STREAM -> "/api/projects/" + step.project() + "/exports/stream?items=" + step.items()
                    + claim(step, runHex);
            case EXPORT_ASYNC -> "/api/projects/" + step.project() + "/exports/async?items=" + step.items()
                    + claim(step, runHex);
            case CUSTOMER_READ -> "/api/customers/" + step.customer();
            case ROLE_GRANT -> "/api/admin/role-grants?project=" + step.project() + "&grantee=" + step.grantee()
                    + "&responsibility=" + (step.responsibility() == null ? "REVIEW" : step.responsibility());
        };
    }

    private static final Pattern FACT_REFERENCE = Pattern.compile("\\{fact:(\\d+)}");

    /** The claimed ticket parameter; {@code {fact:N}} becomes the key {@link #facts} gives to the N-th fact. */
    static String claim(Step step, String runHex) {
        String claimed = step.claimedTicket();
        if (claimed == null || claimed.isBlank()) {
            return "";
        }
        Matcher fact = FACT_REFERENCE.matcher(claimed);
        String key = fact.matches() ? factKey("TCK", runHex, Integer.parseInt(fact.group(1))) : claimed;
        return "&claimedTicket=" + URLEncoder.encode(key, StandardCharsets.UTF_8);
    }

    /** Documentation range (RFC 5737), outside every company and travel network. */
    static final String EXTERNAL_NETWORK = "203.0.113.0/24";

    static String network(ScenarioDefinition scenario, String officeNetwork) {
        return switch (scenario.networkOrDefault()) {
            case OFFICE -> officeNetwork;
            case EXTERNAL -> EXTERNAL_NETWORK;
            case TRAVEL -> scenario.facts().stream().filter(fact -> "TRAVEL".equals(fact.kind())).findFirst()
                    .map(Fact::network)
                    .orElseThrow(() -> new IllegalStateException("Scenario " + scenario.key()
                            + " connects from a travel network but has no TRAVEL fact"));
        };
    }

    static String factKey(String prefix, String runHex, int number) {
        return prefix + "-" + runHex + "-" + number;
    }

    private String document(Step step, String runHex) throws IOException {
        if (step.document().fact() != null) {
            return factKey("DOC", runHex, step.document().fact());
        }
        return admin.document(step.document().project(), step.document().type(), step.document().position());
    }

    static RunFacts facts(ScenarioDefinition scenario, String runHex, Instant companyTime) {
        List<RunFacts.Ticket> tickets = new ArrayList<>();
        List<RunFacts.Approval> approvals = new ArrayList<>();
        List<RunFacts.Oncall> oncall = new ArrayList<>();
        List<RunFacts.TravelPlan> travel = new ArrayList<>();
        List<RunFacts.Document> documents = new ArrayList<>();
        int number = 1;
        for (Fact fact : scenario.facts()) {
            if ("DOCUMENT".equals(fact.kind())) {
                ScenarioDefinition.DocumentText text = fact.document();
                documents.add(new RunFacts.Document(factKey("DOC", runHex, number++), fact.project(), text.type(),
                        text.title().get("en"), "1", text.sensitivity(), text.body().get("en"), text.author(),
                        text.summary().get("en"), LocalDate.parse(text.updatedOn())));
                continue;
            }
            Instant from = companyTime.plus(fact.validFromOffset());
            Instant until = companyTime.plus(fact.validUntilOffset());
            if ("TICKET".equals(fact.kind())) {
                tickets.add(new RunFacts.Ticket(factKey("TCK", runHex, number++), fact.ticketKind(),
                        scenario.protagonist(), fact.approver(), fact.project(), fact.purpose(),
                        fact.purpose() + " on " + fact.project(), from, until, fact.status()));
            } else if ("APPROVAL".equals(fact.kind())) {
                approvals.add(new RunFacts.Approval(factKey("APR", runHex, number++), scenario.protagonist(),
                        fact.approver(), fact.project(), fact.purpose(), fact.maxItems(), from, until, fact.status(),
                        fact.recordedAtOffset() == null ? null : companyTime.plus(fact.recordedAtOffset())));
            } else if ("ONCALL".equals(fact.kind())) {
                oncall.add(new RunFacts.Oncall(factKey("ONC", runHex, number++), scenario.protagonist(), fact.team(),
                        from, until));
            } else if ("TRAVEL".equals(fact.kind())) {
                travel.add(new RunFacts.TravelPlan(factKey("TRV", runHex, number++), scenario.protagonist(),
                        fact.city(), fact.country(), fact.network(), from, until));
            }
        }
        return new RunFacts(tickets, approvals, oncall, travel, documents);
    }

    static boolean rulesAsExpected(Map<String, String> expected, Map<String, String> outcomes) {
        if (expected == null) {
            return true;
        }
        for (Map.Entry<String, String> entry : expected.entrySet()) {
            boolean delivered = "DELIVERED".equals(outcomes.get(entry.getKey()));
            if (("ALLOW".equals(entry.getValue())) != delivered) {
                return false;
            }
        }
        return true;
    }

    /** A host inside the employee's office network: the same /24 as the template, a different address per run. */
    static String hostIn(String network, int host) {
        String base = network.substring(0, network.lastIndexOf('.'));
        return base + "." + host;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted", e);
        }
    }
}
