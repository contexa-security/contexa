package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.spec.ExecutionSpec;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Fact;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Step;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
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

    /** How long a refused step of control D is watched for a decision record before it counts as an earlier one's. */
    static final Duration REFUSED_DECISION_WAIT = Duration.ofSeconds(5);
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
            store.start(new RunStore.RunStart(runId, scenario.key(), scenario.version(), scenario.protagonist(),
                    username, template.map(TemplateStore.ReadyTemplate::templateId).orElse(null), run.organization(),
                    run.tenant(), run.clientIp(), run.device(), companyTime, forcedAction, listener.liveVisitor()));
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

            for (int index = 0; index < scenario.steps().size(); index++) {
                Step step = scenario.steps().get(index);
                int stepNo = index + 1;
                String path = path(step, runHex);
                Instant stepTime = companyTime.plusSeconds(step.offsetSeconds());
                Map<String, String> outcomes = new LinkedHashMap<>();
                StepOutcome engineOutcome = null;
                ControlSession.ChallengeTrace challenge = null;
                for (Control control : Control.values()) {
                    if (control == Control.D && forcedAction != null) {
                        admin.forceAction(username, forcedAction);
                    }
                    StepOutcome outcome = sessions.get(control).send(step.operation(), path, stepTime);
                    store.armResult(runId, stepNo, control, step.operation().name(), outcome);
                    outcomes.put(control.name(), outcome.outcome());
                    listener.stepResult(stepNo, step.operation().name(), control, outcome);
                    if (control == Control.D) {
                        engineOutcome = outcome;
                        if (ControlSession.challenged(outcome)) {
                            challenge = responder.respond(new ChallengeResponder.Challenge(
                                    scenario.oracle().classification(),
                                    outcome.sentAt().plusMillis(outcome.elapsedMs()),
                                    sessions.get(control).challengeActions(username,
                                            username + "@" + CompanyBlueprint.EMAIL_DOMAIN, step.operation(), path,
                                            stepTime, admin)));
                        }
                    }
                }
                EngineDecision decision = engineDecision(step, engineOutcome);
                store.decision(runId, stepNo, engineOutcome.requestId(), decision);
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
                if (scenario.pace() == ScenarioDefinition.Pace.PACED && index < scenario.steps().size() - 1) {
                    sleep(endpoints.allowWindow());
                }
            }
            store.businessEvidence(runId, admin.plainEvidence(runId));
            if (!systemPromptHashes.isEmpty()) {
                ExecutionSpec spec = ExecutionSpecStore.build(admin.engine(), admin.rules(), templateId,
                        systemPromptHashes.get(0), contract.version());
                store.spec(runId, specs.record(spec));
            }
            for (JsonNode call : admin.embeddings(username)) {
                store.cost(runId, null, null, call);
            }
        } catch (IOException | RuntimeException e) {
            log.error("Run failed: runId={}, scenario={}", runId, scenario.key(), e);
            status = "FAILED";
            failure = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            cleanup.putAll(cleanup(runId, username));
            if (started) {
                store.finish(runId, status, failure, cleanup);
            }
        }
        return new RunSummary(runId, scenario.key(), username, organization, status, failure, summaries);
    }

    /**
     * Control D's decision for a step. A synchronous step has its record before the response; an asynchronous one
     * gets it shortly after. A step the engine refused because of an earlier decision gets no record of its own.
     */
    private EngineDecision engineDecision(Step step, StepOutcome outcome) throws IOException {
        if (step.operation() == BusinessOperation.PROJECT_LIST) {
            return EngineDecision.none(json.createObjectNode());
        }
        boolean synchronous = step.operation() == BusinessOperation.EXPORT
                || step.operation() == BusinessOperation.ROLE_GRANT;
        Duration wait = "REFUSED".equals(outcome.outcome()) && !synchronous ? REFUSED_DECISION_WAIT
                : endpoints.decisionWait();
        Instant deadline = Instant.now().plus(wait);
        JsonNode evidence;
        do {
            evidence = admin.decision(outcome.requestId());
            EngineDecision decision = EngineDecision.from(evidence, synchronous);
            if (decision != null) {
                return decision;
            }
            sleep(Duration.ofSeconds(1));
        } while (Instant.now().isBefore(deadline));
        return EngineDecision.none(evidence);
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
            case DOCUMENT_READ -> "/api/documents/" + document(step);
            case DOCUMENT_DOWNLOAD -> "/api/documents/" + document(step) + "/download";
            case EXPORT -> "/api/projects/" + step.project() + "/exports?items=" + step.items() + claim(step, runHex);
            case EXPORT_STREAM -> "/api/projects/" + step.project() + "/exports/stream?items=" + step.items()
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

    private String document(Step step) throws IOException {
        return admin.document(step.document().project(), step.document().type(), step.document().position());
    }

    static RunFacts facts(ScenarioDefinition scenario, String runHex, Instant companyTime) {
        List<RunFacts.Ticket> tickets = new ArrayList<>();
        List<RunFacts.Approval> approvals = new ArrayList<>();
        List<RunFacts.Oncall> oncall = new ArrayList<>();
        List<RunFacts.TravelPlan> travel = new ArrayList<>();
        int number = 1;
        for (Fact fact : scenario.facts()) {
            Instant from = companyTime.plus(fact.validFromOffset());
            Instant until = companyTime.plus(fact.validUntilOffset());
            if ("TICKET".equals(fact.kind())) {
                tickets.add(new RunFacts.Ticket(factKey("TCK", runHex, number++), fact.ticketKind(),
                        scenario.protagonist(), fact.approver(), fact.project(), fact.purpose(),
                        fact.purpose() + " on " + fact.project(), from, until, fact.status()));
            } else if ("APPROVAL".equals(fact.kind())) {
                approvals.add(new RunFacts.Approval(factKey("APR", runHex, number++), scenario.protagonist(),
                        fact.approver(), fact.project(), fact.purpose(), fact.maxItems(), from, until, fact.status()));
            } else if ("ONCALL".equals(fact.kind())) {
                oncall.add(new RunFacts.Oncall(factKey("ONC", runHex, number++), scenario.protagonist(), fact.team(),
                        from, until));
            } else if ("TRAVEL".equals(fact.kind())) {
                travel.add(new RunFacts.TravelPlan(factKey("TRV", runHex, number++), scenario.protagonist(),
                        fact.city(), fact.country(), fact.network(), from, until));
            }
        }
        return new RunFacts(tickets, approvals, oncall, travel);
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
