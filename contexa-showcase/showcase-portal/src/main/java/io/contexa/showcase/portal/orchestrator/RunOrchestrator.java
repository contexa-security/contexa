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
import io.contexa.showcase.portal.agent.AgentTaskProof;
import io.contexa.showcase.portal.agent.AgentTasks;
import io.contexa.showcase.portal.agent.AgentWork;
import io.contexa.showcase.portal.agent.BusinessAgent;
import io.contexa.showcase.portal.agent.BusinessAgentTools;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
    private final AgentTasks agentTasks;

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
        this(endpoints, admin, signer, store, templates, specs, contract, json, anatomies, null);
    }

    /**
     * @param agentTasks docs/agent A7-2b: the business agent of agent tasks; null when this portal runs none
     */
    public RunOrchestrator(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                           RunStore store, TemplateCurrency templates, ExecutionSpecStore specs, ScoringContract contract,
                           ObjectMapper json, AnatomyStore anatomies, AgentTasks agentTasks) {
        this.agentTasks = agentTasks;
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
        // N-SRC-3: the decisions that called the model, which control D seals.
        List<String> sealedRequests = new ArrayList<>();
        Map<String, Object> cleanup = new LinkedHashMap<>();
        String status = "COMPLETED";
        String failure = null;
        boolean started = false;
        String organization = "org-" + runHex;
        RunApprover approver = null;
        // docs/agent A7-0: the run's agent in control D, removed with the run.
        RunAgent agent = null;
        try {
            checkRequestParts(scenario);
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
            approver = new RunApprover(admin, run, runHex, companyTime, () -> new ControlSession(Control.D,
                    new WorkloadClient(endpoints.of(Control.D), signer, run, endpoints.requestTimeout()), json));
            // docs/agent OC-2: the company's integration puts the protagonist's records (with the run's facts) and the
            // company's rules and networks into the engine through its admin API; the engine judges with them.
            approver.putCompanyRecords(admin.companyRecords(username, scenario.protagonist(), runId));
            stageStart = stage(stages, "companyRecords", stageStart);
            if (scenario.agent() != null) {
                agent = new RunAgent(runHex, scenario.agent(), senders(scenario)
                        .contains(ScenarioDefinition.Sender.AGENT_SESSION));
                // docs/agent OC-3: the run's security administrator registers the agent through the engine's API.
                agent.credentials(approver.registerAgent(agent.registration(username)));
                stageStart = stage(stages, "agent", stageStart);
            }

            String templateId = template.map(TemplateStore.ReadyTemplate::templateId).orElse(null);
            List<String> systemPromptHashes = new ArrayList<>();
            Map<Control, ControlSession> sessions = new EnumMap<>(Control.class);
            Instant signInTime = signInTime(scenario, companyTime);
            for (Control control : Control.values()) {
                if (!control.plain()) {
                    stageStart = stage(stages, "plainSignIn", stageStart);
                }
                sessions.put(control, signedIn(control, run, username, password, signInTime));
                if (!control.plain()) {
                    stage(stages, "engineSignIn", stageStart);
                }
            }
            Map<ScenarioDefinition.Sender, ControlSession> agentSessions =
                    agentSessions(agent, scenario, run, username, password, signInTime);
            listener.principalReady(stages);
            // docs/agent OC-1: the company's delegations reach the engine through its delegation admin API, as an
            // application's integration imports them; the engine decides every agent request with them.
            Map<String, String> delegationIds = recordDelegations(facts, agent, run, runHex, approver);

            // W7-4: the request id every control sent each step with, for a later step that sends it again.
            Map<Control, Map<Integer, String>> sent = new EnumMap<>(Control.class);
            // N-INJ-5: the session every step goes in; a step that starts a new one is signed in again before it.
            List<Integer> sessionOfStep = sessionNumbers(scenario);
            // docs/agent A3-8: the security administrator's actions on what the agent learned, before their steps.
            List<Map<String, Object>> learningActions = new ArrayList<>();
            for (int index = 0; index < scenario.steps().size(); index++) {
                Step step = scenario.steps().get(index);
                int stepNo = index + 1;
                if (step.sentByVisitor() && !listener.awaitVisitor(stepNo)) {
                    break;
                }
                if (step.learningAction() != null) {
                    learningActions.add(learningAction(step.learningAction(), stepNo, agent, facts, delegationIds,
                            approver, username, scenario, run));
                }
                String path = path(step, runHex);
                Instant stepTime = companyTime.plusSeconds(step.offsetSeconds());
                if (index > 0 && !sessionOfStep.get(index).equals(sessionOfStep.get(index - 1))) {
                    // The engine leaves a request's own session out of its past records (W3-18): the run's earlier
                    // allowed requests are past records of this step and the later ones.
                    for (Control control : Control.values()) {
                        sessions.put(control, signedIn(control, run, username, password,
                                stepTime.minus(SIGN_IN_LEAD)));
                    }
                    agentSessions = agentSessions(agent, scenario, run, username, password,
                            stepTime.minus(SIGN_IN_LEAD));
                }
                Map<Control, ControlSession.RequestParts> parts = new EnumMap<>(Control.class);
                for (Control control : Control.values()) {
                    parts.put(control, requestParts(json, step, sent.getOrDefault(control, Map.of())));
                }
                Map<Control, ControlResult> results = dispatch(new StepCall(runId, username, scenario, step, stepNo,
                        path, stepTime, forcedAction, responder, listener, approver, parts),
                        sessionsOf(step, sessions, agentSessions));
                for (Control control : Control.values()) {
                    sent.computeIfAbsent(control, ignored -> new LinkedHashMap<>())
                            .put(stepNo, results.get(control).outcome().requestId());
                }
                summaries.add(recordStep(runId, username, step, stepNo, path, results, systemPromptHashes,
                        sealedRequests));
                // In a live run a step the visitor sends goes when the visitor presses, not after the pacing wait.
                if (scenario.pace() == ScenarioDefinition.Pace.PACED && index < scenario.steps().size() - 1
                        && !(scenario.steps().get(index + 1).sentByVisitor() && listener.liveVisitor() != null)) {
                    sleep(endpoints.allowWindow());
                }
            }
            // docs/agent A7-2d: the business agent's work comes after the case's scripted steps (a stolen token is
            // used after the agent's own work), its steps numbered after theirs.
            if (scenario.task() != null) {
                if (scenario.task().startsNewSession()) {
                    // A work on a later day than the scripted steps goes in a session of its own, as a step that
                    // starts one: the agent's earlier sessions are its history (docs/agent A4).
                    Instant workTime = companyTime.plusSeconds(workOffset(scenario));
                    for (Control control : Control.values()) {
                        sessions.put(control, signedIn(control, run, username, password,
                                workTime.minus(SIGN_IN_LEAD)));
                    }
                    agentSessions = agentSessions(agent, scenario, run, username, password,
                            workTime.minus(SIGN_IN_LEAD));
                }
                agentTask(runId, username, scenario, companyTime, forcedAction, responder, listener, approver,
                        sessions, agentSessions, summaries, systemPromptHashes, sealedRequests);
            }
            if (!learningActions.isEmpty()) {
                cleanup.put("agentLearning", learningActions);
            }
            for (StepSummary summary : summaries) {
                collectExchanges(runId, summary.stepNo(), summary.requestId());
            }
            // N-SRC-3: inspected while the records the source checks read are still there (the clean-up removes them).
            cleanup.put("sealInspection", inspectSealed(sealedRequests, admin::inspectSealed, SEAL_INSPECTION_WAIT,
                    SEAL_INSPECTION_ATTEMPTS));
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
            if (agent != null) {
                try {
                    cleanup.put("agent", approver.removeAgent(agent.agentId()));
                } catch (IOException | RuntimeException e) {
                    log.error("Agent cleanup failed: runId={}", runId, e);
                    cleanup.put("agentError", e.getMessage());
                }
            }
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

    /**
     * The records of a step every control answered: control D's decision, its model calls and sealed prompts, its
     * additional check or release, and the step's summary. Shared by scripted steps and an agent's requests.
     */
    private StepSummary recordStep(String runId, String username, Step step, int stepNo, String path,
                                   Map<Control, ControlResult> results, List<String> systemPromptHashes,
                                   List<String> sealedRequests) throws IOException {
        return recordStep(runId, username, step, stepNo, path, results, systemPromptHashes, sealedRequests, null);
    }

    /** @param decisionsBy the latest a decision record is waited for; null for the step's own wait from now */
    private StepSummary recordStep(String runId, String username, Step step, int stepNo, String path,
                                   Map<Control, ControlResult> results, List<String> systemPromptHashes,
                                   List<String> sealedRequests, Instant decisionsBy) throws IOException {
        Map<String, String> outcomes = new LinkedHashMap<>();
        for (Control control : Control.values()) {
            outcomes.put(control.name(), results.get(control).outcome().outcome());
        }
        StepOutcome engineOutcome = results.get(Control.D).outcome();
        ControlSession.ChallengeTrace challenge = results.get(Control.D).challenge();
        EngineDecision decision = engineDecision(step, engineOutcome, decisionsBy);
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
        if (!decision.raw().path("modelCalls").isEmpty()) {
            sealedRequests.add(engineOutcome.requestId());
        }
        return new StepSummary(stepNo, step.operation().name(), path, outcomes, step.expected(),
                rulesAsExpected(step.expected(), outcomes), decision.finalAction(), decision.applied(),
                decision.unresolved(), engineOutcome.requestId(), firstPromptSha(decision),
                foreignPrincipals(decision, username), challengeSummary);
    }

    /** docs/agent A7-2b: who sends the case's requests: its steps' senders and its agent task's. */
    static Set<ScenarioDefinition.Sender> senders(ScenarioDefinition scenario) {
        Set<ScenarioDefinition.Sender> senders = EnumSet.noneOf(ScenarioDefinition.Sender.class);
        scenario.steps().forEach(step -> senders.add(step.senderOrPerson()));
        if (scenario.task() != null && scenario.task().sender() != null) {
            senders.add(scenario.task().sender());
        }
        return senders;
    }

    /** One request an agent's work sent, as every control answered it, recorded once the work is done. */
    private record SentStep(int stepNo, Step step, String path, Map<Control, ControlResult> results) {
    }

    /**
     * docs/agent A7-2b: the case's business agent does the work the person gave it. Each of its tool calls is a step:
     * one real request sent to every control at once (control D from the agent's sender, the rule controls from the
     * person's session, as A7-0), at the company time the work has reached; the agent receives control D's answer.
     * The decisions are recorded once the work is done, so the agent works at its own pace as a real agent would.
     */
    private void agentTask(String runId, String username, ScenarioDefinition scenario, Instant companyTime,
                           String forcedAction, ChallengeResponder responder, RunListener listener, Approver approver,
                           Map<Control, ControlSession> sessions,
                           Map<ScenarioDefinition.Sender, ControlSession> agentSessions, List<StepSummary> summaries,
                           List<String> systemPromptHashes, List<String> sealedRequests) throws IOException {
        ScenarioDefinition.AgentTask task = scenario.task();
        if (agentTasks == null) {
            throw new IllegalStateException("This portal runs no business agent");
        }
        if (task.sender() == null || task.sender() == ScenarioDefinition.Sender.PERSON) {
            throw new IllegalArgumentException("An agent task is sent by the case's agent");
        }
        Map<ScenarioDefinition.Sender, ControlSession> workSessions = new EnumMap<>(agentSessions);
        if (task.runtime() != null) {
            if (task.sender() == ScenarioDefinition.Sender.AGENT_SESSION) {
                throw new IllegalArgumentException("Only an agent token can be used by another agent runtime");
            }
            workSessions.put(task.sender(), agentSessions.get(task.sender()).carriedTo(
                    hostIn(task.runtime().network(), 10 + random.nextInt(200)), task.runtime().userAgent()));
        }
        ControlSession agentSession = workSessions.get(task.sender());
        List<SentStep> sentSteps = Collections.synchronizedList(new ArrayList<>());
        // docs/agent A7-3: the first request of the work control D asked the delegating person to confirm.
        AtomicReference<PendingConfirmation> pending = new AtomicReference<>();
        AtomicInteger steps = new AtomicInteger(scenario.steps().size());
        long workOffset = workOffset(scenario);
        Instant workStarted = Instant.now();
        AgentWork.Sender sender = request -> {
            int stepNo = steps.incrementAndGet();
            Step step = new Step(request.operation(), null, request.project(), request.customer(), request.items(),
                    workOffset + Duration.between(workStarted, Instant.now()).toSeconds(), Map.of(), null,
                    request.grantee(), request.responsibility(), null, null, null, null, null, task.sender(), null);
            String path = agentPath(request);
            Map<Control, ControlResult> results = dispatch(new StepCall(runId, username, scenario, step, stepNo, path,
                    companyTime.plusSeconds(step.offsetSeconds()), forcedAction, responder, listener, approver,
                    noParts()), sessionsOf(step, sessions, workSessions));
            sentSteps.add(new SentStep(stepNo, step, path, results));
            String body = agentSession.lastBody();
            if (ControlSession.agentConfirmationRequired(results.get(Control.D).outcome())) {
                pending.compareAndSet(null, new PendingConfirmation(stepNo, step, path, body, Instant.now(),
                        companyTime.plusSeconds(step.offsetSeconds())));
            }
            return answer(stepNo, path, results, body);
        };
        BusinessAgentTools tools = new BusinessAgentTools(sender, task.maxToolCalls() != null ? task.maxToolCalls()
                : agentTasks.maxToolCalls());
        Set<String> toolNames = task.tools().stream().map(BusinessAgentTools.TOOL_OF_OPERATION::get)
                .filter(Objects::nonNull).collect(Collectors.toSet());
        String instruction = task.instruction().getOrDefault("en", task.instruction().values().stream().findFirst()
                .orElse(""));
        AgentWork.Transcript transcript = agentTasks.agent().run(agentTasks.models().modelOf(task.model()),
                task.agentPrompt() != null ? task.agentPrompt() : BusinessAgent.DEFAULT_PROMPT, instruction, tools,
                toolNames, task.maxSeconds() != null ? Duration.ofSeconds(task.maxSeconds()) : agentTasks.maxTime());
        List<SentStep> recorded;
        synchronized (sentSteps) {
            recorded = List.copyOf(sentSteps);
        }
        // docs/agent A7-2 (real server 2026-10-23): a request answered by the decision in force for the session (an
        // ALLOW still valid, N-SES-1) gets no decision record of its own, and an agent sends many within that window;
        // the work's decisions are waited for once, from the end of the work, not once per request.
        Instant decisionsBy = Instant.now().plus(endpoints.decisionWait());
        for (SentStep sentStep : recorded) {
            summaries.add(recordStep(runId, username, sentStep.step(), sentStep.stepNo(), sentStep.path(),
                    sentStep.results(), systemPromptHashes, sealedRequests, decisionsBy));
        }
        AgentTaskProof.Proof proof = AgentTaskProof.of(task, transcript,
                Arrays.stream(Control.values()).map(Control::name).toList());
        store.agentTask(runId, task.sender().name(), transcript, proof);
        // docs/agent A7-3: the delegating person answers the confirmation while the run's accounts still exist.
        if (pending.get() != null) {
            store.agentConfirmation(runId, pending.get().stepNo(), confirm(pending.get(), scenario, responder,
                    agentSession, sessions.get(Control.D)));
        }
    }

    /** docs/agent A7-3: a request of the agent's work control D asked its delegating person to confirm. */
    private record PendingConfirmation(int stepNo, Step step, String path, String body, Instant askedAt,
                                       Instant companyTime) {
    }

    /**
     * docs/agent A7-3: the confirmation control D asked, answered by the delegating person in the person's own
     * session of control D (or by nobody); the agent then sends the request again with it. The company time goes on
     * from the request's as the real time does.
     */
    private ControlSession.AgentConfirmationTrace confirm(PendingConfirmation pending, ScenarioDefinition scenario,
                                                          ChallengeResponder responder, ControlSession agent,
                                                          ControlSession person) {
        JsonNode body;
        try {
            body = json.readTree(pending.body() == null ? "{}" : pending.body());
        } catch (IOException e) {
            body = json.createObjectNode();
        }
        String id = text(body, "confirmationId");
        String trigger = text(body, "trigger");
        String expiresAt = text(body, "expiresAt");
        if (id == null) {
            // No person is accountable for the agent, so the engine asked nobody.
            return ControlSession.AgentConfirmationTrace.notAsked(null, trigger, expiresAt, pending.askedAt())
                    .unanswered("NO_CONFIRMATION");
        }
        Supplier<Instant> companyTime = () -> pending.companyTime()
                .plus(Duration.between(pending.askedAt(), Instant.now()));
        AgentConfirmationActions actions = agent.agentConfirmationActions(id, pending.step().operation(),
                pending.path(), person, BusinessOperation.PROJECT_LIST, "/api/projects", companyTime);
        return responder.confirmAgent(new ChallengeResponder.AgentConfirmation(
                scenario.oracle().classification(), pending.stepNo(), id, trigger, expiresAt, pending.askedAt(),
                ControlSession.method(pending.step().operation()), pending.path(), actions));
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() || value.asText().isBlank() ? null : value.asText();
    }

    /**
     * docs/agent A7-2d: when the agent's work starts after the case's company time: when the case says, else a minute
     * after its last scripted step, else at once.
     */
    static long workOffset(ScenarioDefinition scenario) {
        if (scenario.task().offsetSeconds() != null) {
            return scenario.task().offsetSeconds();
        }
        return scenario.steps().isEmpty() ? 0
                : scenario.steps().get(scenario.steps().size() - 1).offsetSeconds() + 60;
    }

    private static Map<Control, ControlSession.RequestParts> noParts() {
        Map<Control, ControlSession.RequestParts> parts = new EnumMap<>(Control.class);
        for (Control control : Control.values()) {
            parts.put(control, ControlSession.RequestParts.NONE);
        }
        return parts;
    }

    /** What every control answered to an agent's request, with control D's answer as the agent receives it. */
    private static AgentWork.Answer answer(int stepNo, String path, Map<Control, ControlResult> results, String body) {
        Map<String, String> outcomes = new LinkedHashMap<>();
        Map<String, Integer> items = new LinkedHashMap<>();
        Map<String, String> excerpts = new LinkedHashMap<>();
        for (Control control : Control.values()) {
            StepOutcome outcome = results.get(control).outcome();
            outcomes.put(control.name(), outcome.outcome());
            items.put(control.name(), outcome.deliveredItems());
            excerpts.put(control.name(), outcome.excerpt());
        }
        StepOutcome engine = results.get(Control.D).outcome();
        return new AgentWork.Answer(stepNo, path, engine.httpStatus() != null ? engine.httpStatus() : 0,
                engine.outcome(), engine.ruleId(), body, outcomes, items, excerpts);
    }

    /** The path of an agent's request; what the agent names is sent as it named it, encoded. */
    static String agentPath(AgentWork.Request request) {
        return switch (request.operation()) {
            case PROJECT_LIST -> "/api/projects";
            case DOCUMENT_LIST -> "/api/projects/" + segment(request.project()) + "/documents"
                    + query("type", request.type(), "q", request.query());
            case DOCUMENT_READ -> "/api/documents/" + segment(request.document());
            case DOCUMENT_DOWNLOAD -> "/api/documents/" + segment(request.document()) + "/download";
            case EXPORT, EXPORT_ASYNC -> "/api/projects/" + segment(request.project())
                    + (request.operation() == BusinessOperation.EXPORT_ASYNC ? "/exports/async" : "/exports")
                    + "?items=" + (request.items() == null ? "" : request.items());
            case EXPORT_STREAM -> "/api/projects/" + segment(request.project()) + "/exports/stream?items="
                    + (request.items() == null ? "" : request.items());
            case CUSTOMER_READ -> "/api/customers/" + segment(request.customer());
            case ROLE_GRANT -> "/api/admin/role-grants" + query("project", request.project(), "grantee",
                    request.grantee(), "responsibility", request.responsibility());
        };
    }

    private static String segment(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String query(String... pairs) {
        StringBuilder query = new StringBuilder();
        for (int index = 0; index + 1 < pairs.length; index += 2) {
            if (pairs[index + 1] == null || pairs[index + 1].isBlank()) {
                continue;
            }
            query.append(query.isEmpty() ? '?' : '&').append(pairs[index]).append('=')
                    .append(URLEncoder.encode(pairs[index + 1], StandardCharsets.UTF_8));
        }
        return query.toString();
    }

    /**
     * docs/agent A3-8: the run's security administrator acts on what the case's agent learned, through the engine's
     * administrator API, and the person's learning is read before and after: the action must leave it as it was.
     * Recorded with the run (its clean-up record) with the engine's answer and the learning states of the agent's
     * decision records after the action.
     */
    private Map<String, Object> learningAction(ScenarioDefinition.LearningAction action, int stepNo, RunAgent agent,
                                               RunFacts facts, Map<String, String> delegationIds, Approver approver,
                                               String username, ScenarioDefinition scenario, RunIdentity run)
            throws IOException {
        if (agent == null) {
            throw new IllegalStateException("A learning action needs the case's agent: step " + stepNo);
        }
        String delegationId = null;
        if (action.forDelegation()) {
            if (facts.delegations().isEmpty()) {
                throw new IllegalStateException("A delegation's learning action needs the case's delegation");
            }
            delegationId = delegationIds.get(facts.delegations().get(0).delegationKey());
        }
        JsonNode before = admin.snapshot(username, scenario.protagonist(), run.organization(), run.tenant());
        Approver.LearningResult result = approver.agentLearning(agent.agentId(), delegationId, action.action(),
                action.reason());
        JsonNode after = admin.snapshot(username, scenario.protagonist(), run.organization(), run.tenant());
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("beforeStep", stepNo);
        entry.put("action", action.action());
        entry.put("agentId", agent.agentId());
        entry.put("delegationId", delegationId);
        entry.put("status", result.status());
        entry.put("answer", result.answer());
        entry.put("personLearningUnchanged", personLearning(before).equals(personLearning(after)));
        entry.put("personDocuments", personLearning(after).path("documents").size());
        List<String> agentStates = new ArrayList<>();
        for (JsonNode document : after.path("behaviourDocuments")) {
            JsonNode metadata = document.path("metadata");
            if (agent.agentId().equals(metadata.path("agentId").asText(null))) {
                agentStates.add(metadata.path("learningState").asText("LEARNED"));
            }
        }
        entry.put("agentRecordStatesAfter", agentStates);
        if (result.status() != 200) {
            throw new IOException("The learning action before step " + stepNo + " answered " + result.status());
        }
        return entry;
    }

    /**
     * docs/agent OC-1: records the run's delegations through the engine's delegation admin API, with the company's
     * times (who wrote each and when, the period); the engine's identifier of each by the run's delegation key.
     */
    private static Map<String, String> recordDelegations(RunFacts facts, RunAgent agent, RunIdentity run,
                                                         String runHex, Approver approver) throws IOException {
        Map<String, String> ids = new LinkedHashMap<>();
        if (facts.delegations().isEmpty()) {
            return ids;
        }
        if (agent == null) {
            throw new IllegalStateException("A delegation fact needs the case's agent");
        }
        for (RunFacts.Delegation delegation : facts.delegations()) {
            if (delegation.revoked()) {
                throw new IllegalStateException("A revoked delegation fact has no import yet: "
                        + delegation.delegationKey());
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("tenantId", run.tenant());
            body.put("delegatorId", "v" + runHex + "-" + delegation.delegator());
            body.put("agentId", agent.agentId());
            body.put("objectiveId", delegation.objectiveId());
            body.put("objectiveFamily", delegation.objectiveFamily());
            body.put("objectiveSummary", delegation.summary());
            body.put("allowedOperations", delegation.operations());
            body.put("allowedResources", delegation.resources());
            body.put("approvalRequired", delegation.approvalRequired());
            body.put("validFrom", delegation.validFrom().toString());
            body.put("expiresAt", delegation.expiresAt().toString());
            body.put("recordedBy", delegation.recordedBy() != null ? "v" + runHex + "-" + delegation.recordedBy()
                    : null);
            body.put("recordedAt", delegation.recordedAt() != null ? delegation.recordedAt().toString() : null);
            ids.put(delegation.delegationKey(), approver.recordDelegation(body));
        }
        return ids;
    }

    /** The person's own learning in a snapshot: the baseline, the work profile and the records of no agent. */
    private JsonNode personLearning(JsonNode snapshot) {
        ObjectNode learning = json.createObjectNode();
        learning.set("userBaseline", snapshot.path("userBaseline"));
        learning.set("workProfileObservations", snapshot.path("workProfileObservations"));
        ArrayNode documents = learning.putArray("documents");
        for (JsonNode document : snapshot.path("behaviourDocuments")) {
            if (!document.path("metadata").hasNonNull("agentId")) {
                documents.add(document);
            }
        }
        return learning;
    }

    /**
     * docs/agent A7-0: control D's session of each agent sender the case uses, from the agent's own network and user
     * agent: the agent acting for the person (an exchanged token), on its own (its client credentials token) and with
     * its own account. Empty for a case without an agent.
     */
    private Map<ScenarioDefinition.Sender, ControlSession> agentSessions(RunAgent agent, ScenarioDefinition scenario,
                                                                         RunIdentity run, String username,
                                                                         String password, Instant at)
            throws IOException {
        Map<ScenarioDefinition.Sender, ControlSession> agentSessions = new EnumMap<>(ScenarioDefinition.Sender.class);
        if (agent == null) {
            return agentSessions;
        }
        RunIdentity agentRun = new RunIdentity(run.runId(), run.organization(), run.tenant(),
                hostIn(agent.definition().network(), 10 + random.nextInt(200)), agent.definition().userAgent());
        WorkloadClient agentClient = new WorkloadClient(endpoints.of(Control.D), signer, agentRun,
                endpoints.requestTimeout());
        for (ScenarioDefinition.Sender sender : senders(scenario)) {
            if (sender == ScenarioDefinition.Sender.PERSON || agentSessions.containsKey(sender)) {
                continue;
            }
            agentSessions.put(sender, switch (sender) {
                case DELEGATED_AGENT -> agent.delegated(agentClient.freshSession(run),
                        agentClient.freshSession(agentRun), username, password, at, admin, json);
                case AUTONOMOUS_AGENT -> agent.autonomous(agentClient.freshSession(agentRun), at, json);
                case AGENT_SESSION -> agent.session(agentClient.freshSession(agentRun), at, admin, json);
                case PERSON -> throw new IllegalStateException("The person has no agent session");
            });
        }
        return agentSessions;
    }

    /**
     * docs/agent A7-0: the sessions a step goes in. Control D receives it from its sender; the rule controls know no
     * agents and receive every step from the person's session, as an agent using the person's credentials reaches
     * them today.
     */
    static Map<Control, ControlSession> sessionsOf(Step step, Map<Control, ControlSession> sessions,
                                                   Map<ScenarioDefinition.Sender, ControlSession> agentSessions) {
        ScenarioDefinition.Sender sender = step.senderOrPerson();
        if (sender == ScenarioDefinition.Sender.PERSON) {
            return sessions;
        }
        ControlSession agentSession = agentSessions.get(sender);
        if (agentSession == null) {
            throw new IllegalStateException("The case sends a step as " + sender + " but has no agent");
        }
        Map<Control, ControlSession> stepSessions = new EnumMap<>(sessions);
        stepSessions.put(Control.D, agentSession);
        return stepSessions;
    }

    /** The run principal signed in to a control in a session of its own: the run's first, or one a step starts. */
    private ControlSession signedIn(Control control, RunIdentity run, String username, String password, Instant at)
            throws IOException {
        ControlSession session = new ControlSession(control,
                new WorkloadClient(endpoints.of(control), signer, run, endpoints.requestTimeout()), json);
        if (control.plain()) {
            session.signInPlain(username, password, at);
        } else {
            session.signInEngine(username, password, username + "@" + CompanyBlueprint.EMAIL_DOMAIN, at, admin);
        }
        return session;
    }

    /**
     * One step of a run as every control receives it.
     *
     * @param parts W7-4: the request parts each control sends the step with
     */
    private record StepCall(String runId, String username, ScenarioDefinition scenario, Step step, int stepNo,
                            String path, Instant stepTime, String forcedAction, ChallengeResponder responder,
                            RunListener listener, Approver approver, Map<Control, ControlSession.RequestParts> parts) {
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
                call.parts().get(control), new ControlSession.SendListener() {
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
        // docs/agent A7-0: an agent's step gets no person's one-time code and no person's release.
        boolean personSends = call.step().senderOrPerson() == ScenarioDefinition.Sender.PERSON;
        if (control == Control.D && personSends && ControlSession.challenged(outcome)) {
            challenge = call.responder().respond(new ChallengeResponder.Challenge(
                    call.scenario().oracle().classification(), call.scenario().oracle().ownerActs(),
                    outcome.sentAt().plusMillis(outcome.elapsedMs()),
                    session.challengeActions(call.username(), email, call.step().operation(), call.path(),
                            call.parts().get(control), call.stepTime(), admin)));
        } else if (control == Control.D && personSends && ControlSession.blocked(outcome)) {
            release = call.responder().release(new ChallengeResponder.Release(
                    call.scenario().oracle().classification(),
                    outcome.sentAt().plusMillis(outcome.elapsedMs()), call.username(),
                    session.releaseActions(call.username(), email, call.step().operation(), call.path(),
                            call.parts().get(control), call.stepTime(), admin),
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
    private EngineDecision engineDecision(Step step, StepOutcome outcome, Instant decisionsBy) throws IOException {
        if (step.operation() == BusinessOperation.PROJECT_LIST) {
            return EngineDecision.none(json.createObjectNode());
        }
        boolean synchronous = EngineDecision.synchronous(step.operation());
        Duration wait = "REFUSED".equals(outcome.outcome()) && !synchronous ? REFUSED_DECISION_WAIT
                : endpoints.decisionWait();
        Instant own = Instant.now().plus(wait);
        Instant deadline = decisionsBy != null && decisionsBy.isBefore(own) ? decisionsBy : own;
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
        boolean documentStep = step.operation() == BusinessOperation.DOCUMENT_READ
                || step.operation() == BusinessOperation.DOCUMENT_DOWNLOAD;
        return path(step, runHex, documentStep ? document(step, runHex) : null);
    }

    /** The path and query a step is sent to; {@code documentKey} names the document of a document step (W7-4). */
    static String path(Step step, String runHex, String documentKey) {
        return switch (step.operation()) {
            case PROJECT_LIST -> "/api/projects";
            case DOCUMENT_READ -> "/api/documents/" + documentKey;
            case DOCUMENT_DOWNLOAD -> "/api/documents/" + documentKey + "/download";
            case EXPORT -> "/api/projects/" + step.project() + "/exports?items=" + step.items() + claim(step, runHex);
            case EXPORT_STREAM -> "/api/projects/" + step.project() + "/exports/stream?items=" + step.items()
                    + claim(step, runHex);
            case EXPORT_ASYNC -> "/api/projects/" + step.project() + "/exports/async?items=" + step.items()
                    + claim(step, runHex);
            case CUSTOMER_READ -> "/api/customers/" + step.customer();
            case ROLE_GRANT -> "/api/admin/role-grants?project=" + step.project() + "&grantee=" + step.grantee()
                    + "&responsibility=" + (step.responsibility() == null ? "REVIEW" : step.responsibility());
            // docs/agent A7-2a: the documents of a project, of one type when the step names it.
            case DOCUMENT_LIST -> "/api/projects/" + step.project() + "/documents"
                    + (step.document() != null && step.document().type() != null
                    ? "?type=" + URLEncoder.encode(step.document().type(), StandardCharsets.UTF_8) : "");
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

    /** N-INJ-5: how long before a session's first request the run principal signs in to it. */
    static final Duration SIGN_IN_LEAD = Duration.ofMinutes(2);

    /**
     * N-INJ-5: when the run principal signs in to the run's first session: two minutes before the company time, or two
     * minutes before the first step when that step comes earlier (a read the definition puts before the case's time).
     */
    static Instant signInTime(ScenarioDefinition scenario, Instant companyTime) {
        Instant at = companyTime.minus(SIGN_IN_LEAD);
        if (scenario.steps().isEmpty()) {
            return at;
        }
        Instant first = companyTime.plusSeconds(scenario.steps().get(0).offsetSeconds());
        return first.isAfter(at) ? at : first.minus(SIGN_IN_LEAD);
    }

    /**
     * N-INJ-5: the session (1-based) each step of a definition is sent in: the run signs in before its first step, and
     * again before every later step that starts a new session.
     */
    static List<Integer> sessionNumbers(ScenarioDefinition scenario) {
        List<Integer> numbers = new ArrayList<>();
        int session = 1;
        for (int index = 0; index < scenario.steps().size(); index++) {
            if (index > 0 && scenario.steps().get(index).startsNewSession()) {
                session++;
            }
            numbers.add(session);
        }
        return List.copyOf(numbers);
    }

    /** W7-4: the header a step sends the request id of an earlier step in (plan 8.7). */
    static final String CLIENT_REQUEST_ID = "X-Request-ID";

    /**
     * W7-4: refuses a definition whose request parts cannot be sent as written, before anything of its run is
     * created: a body on a GET step, a header of the signed internal context or the run's device, or a request id taken
     * from a step that is not an earlier one or beside an X-Request-ID the step names itself. N-INJ-5: and a first step
     * that starts a new session (the run signs in before its first step).
     */
    static void checkRequestParts(ScenarioDefinition scenario) {
        for (int index = 0; index < scenario.steps().size(); index++) {
            Step step = scenario.steps().get(index);
            int stepNo = index + 1;
            if (index == 0 && step.startsNewSession()) {
                throw new IllegalArgumentException("Step 1 of " + scenario.key() + " starts a new session, but the"
                        + " run signs in before its first step");
            }
            if (step.body() != null && !"POST".equals(ControlSession.method(step.operation()))) {
                throw new IllegalArgumentException("Step " + stepNo + " of " + scenario.key()
                        + " sends a body with a GET request");
            }
            Map<String, String> headers = step.headers() == null ? Map.of() : step.headers();
            for (String name : headers.keySet()) {
                if (WorkloadClient.isReservedHeader(name)) {
                    throw new IllegalArgumentException("Step " + stepNo + " of " + scenario.key() + " adds header "
                            + name + " of the run's signed context");
                }
            }
            if (step.requestIdOf() != null) {
                if (step.requestIdOf() < 1 || step.requestIdOf() >= stepNo) {
                    throw new IllegalArgumentException("Step " + stepNo + " of " + scenario.key()
                            + " takes the request id of step " + step.requestIdOf() + ", which is not an earlier one");
                }
                if (headers.keySet().stream().anyMatch(CLIENT_REQUEST_ID::equalsIgnoreCase)) {
                    throw new IllegalArgumentException("Step " + stepNo + " of " + scenario.key()
                            + " names its X-Request-ID twice");
                }
            }
        }
    }

    /**
     * W7-4: the request parts of a step at one control (plan 8.7): its body as JSON, the headers it names and, when it
     * takes the request id of an earlier step, the id this control sent that step with as its X-Request-ID. The request
     * still gets a fresh processing id of its own in the signed internal context (ControlSession.send): the engine
     * takes its processing id only from that context and never from a client X-Request-ID, and run_decision.request_id
     * and every decision lookup key on it, so a repeated X-Request-ID never makes two steps one record.
     *
     * @param sent the request ids this control sent the earlier steps of the run with, by step number
     */
    static ControlSession.RequestParts requestParts(ObjectMapper json, Step step, Map<Integer, String> sent)
            throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        if (step.headers() != null) {
            headers.putAll(step.headers());
        }
        if (step.requestIdOf() != null) {
            String earlier = sent.get(step.requestIdOf());
            if (earlier == null) {
                throw new IllegalStateException("Step " + step.requestIdOf() + " sent no request whose id could be"
                        + " repeated");
            }
            headers.put(CLIENT_REQUEST_ID, earlier);
        }
        String body = step.body() == null ? null : json.writeValueAsString(step.body());
        return body == null && headers.isEmpty() ? ControlSession.RequestParts.NONE
                : new ControlSession.RequestParts(body, headers);
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
        List<RunFacts.Delegation> delegations = new ArrayList<>();
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
            } else if ("DELEGATION".equals(fact.kind())) {
                // docs/agent A7-0: the work the protagonist delegated to the run's agent.
                if (scenario.agent() == null || fact.delegated() == null) {
                    throw new IllegalArgumentException("A DELEGATION fact needs the case's agent and what it delegates");
                }
                ScenarioDefinition.Delegated delegated = fact.delegated();
                String key = factKey("DLG", runHex, number++);
                // A2-10: the protagonist wrote the record when the delegation began, or when the case says.
                delegations.add(new RunFacts.Delegation(key, scenario.protagonist(),
                        RunAgent.agentId(runHex, scenario.agent().name()), key, fact.purpose(),
                        delegated.summary() != null ? delegated.summary().get("en") : null, delegated.operations(),
                        delegated.resources(), delegated.approvalRequired(), from, until,
                        "REVOKED".equals(fact.status()), scenario.protagonist(),
                        fact.recordedAtOffset() == null ? from : companyTime.plus(fact.recordedAtOffset())));
            }
        }
        return new RunFacts(tickets, approvals, oncall, travel, documents, delegations);
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

    /** N-SRC-3: how often and how long apart a sealed decision not stored yet is asked for again. */
    static final int SEAL_INSPECTION_ATTEMPTS = 20;
    static final Duration SEAL_INSPECTION_WAIT = Duration.ofMillis(250);

    /** N-SRC-3: how the run asks control D to inspect a sealed decision now; empty while it is not stored. */
    interface SealInspector {
        Optional<JsonNode> inspect(String requestId) throws IOException;
    }

    /**
     * N-SRC-3: the run's sealed decisions inspected before the run is cleaned up, while the records the source checks
     * read are still there. A package not stored yet is asked for again after the wait, up to the attempts; an error
     * stops asking for that decision and does not fail the run. Gives the counts the cleanup record keeps.
     */
    static Map<String, Object> inspectSealed(List<String> requestIds, SealInspector inspector, Duration wait,
                                             int attempts) {
        int inspected = 0;
        List<String> missing = new ArrayList<>();
        for (String requestId : requestIds) {
            boolean done = false;
            for (int attempt = 0; attempt < attempts && !done; attempt++) {
                try {
                    done = inspector.inspect(requestId).isPresent();
                } catch (IOException | RuntimeException e) {
                    log.error("Sealed decision could not be inspected: requestId={}", requestId, e);
                    break;
                }
                if (!done && attempt < attempts - 1) {
                    sleep(wait);
                }
            }
            if (done) {
                inspected++;
            } else {
                missing.add(requestId);
            }
        }
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("requested", requestIds.size());
        counts.put("inspected", inspected);
        counts.put("missing", List.copyOf(missing));
        return counts;
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
