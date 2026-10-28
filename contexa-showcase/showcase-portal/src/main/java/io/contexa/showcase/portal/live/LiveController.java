package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.anatomy.BeforeSend;
import io.contexa.showcase.portal.anatomy.CoreAdverseLabels;
import io.contexa.showcase.portal.anatomy.SealedDeviations;
import io.contexa.showcase.portal.combination.Combination;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.EngineDecision;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.BurstChoice;
import io.contexa.showcase.portal.scenario.DelegationChoice;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Visitor API of live runs (deck p.12, p.13, docs/showcase/P4-설계.md). It exists only with
 * {@code showcase.live.enabled=true}; the visitor is the one of the signed visitor cookie, every change is a POST under
 * the CSRF token, and every new run passes the cost gate. The client address is the request's remote address, which a
 * production portal takes from its trusted proxy only.
 */
@RestController
@ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
public class LiveController {

    /** Shape of a generated employee key (CompanyGenerator), checked before any lookup. */
    private static final Pattern EMPLOYEE_KEY = Pattern.compile("[a-z]{3}-[a-z0-9]{1,2}");

    /**
     * @param subject who sends the case's requests: PERSON, or AGENT for a case whose work a business agent does
     *                (docs/agent Agent중심-화면 AS-6); a field added to the answer, the others are as they were
     */
    public record ScenarioOption(String key, Map<String, String> title, String classification, String subject) {

        static ScenarioOption of(ScenarioDefinition scenario) {
            return new ScenarioOption(scenario.key(), scenario.title(), scenario.oracle().classification(),
                    scenario.task() != null ? "AGENT" : "PERSON");
        }
    }

    /**
     * @param delegation docs/agent Agent중심-화면 AS-12: one of the fixed changes of the delegation of the editable case;
     *                   null for the case as it is. A value outside the lists is refused when the request is read.
     * @param copies     docs/agent AS-13: the requests a live burst sends at once, 1 to ten; only the burst case takes
     *                   it, and takes no start without it
     */
    public record StartRequest(String scenario, String turnstileToken, DelegationChoice delegation, Integer copies) {

        public StartRequest(String scenario, String turnstileToken) {
            this(scenario, turnstileToken, null, null);
        }
    }

    public record CombinationRequest(String key, String turnstileToken) {
    }

    public record AnswerRequest(String code) {
    }

    /** docs/agent A7-3: the visitor's answer, as the delegating employee, to a confirmation of the agent's request. */
    public record AgentConfirmationAnswer(boolean approve) {
    }

    public record ReleaseRequest(String reason) {
    }

    private final LiveRuns live;
    private final LiveGate gate;
    private final LiveQuota quota;
    private final LiveAllotment allotment;
    private final TurnstileVerifier turnstile;
    private final ScenarioCatalog scenarios;
    /** docs/agent A7-3: the business agent cases a visitor can start (the agent group), apart from the catalog. */
    private final AgentTaskCatalog agentTasks;
    private final List<String> agentTaskKeys;
    /** The agent cases a start may name: the open ones and the one whose delegation a visitor may edit. */
    private final List<String> startableAgentKeys;
    private final String editableCase;
    /** docs/agent AS-13: the case a visitor may send a burst of (live up to ten requests at once); null for none. */
    private final String burstCase;
    private final VisitorCookies cookies;
    private final ReplayViews views;
    private final WorkloadAdmin admin;
    private final TemplateCurrency templates;
    private final ObjectMapper json;
    private final Map<String, BaselineCard.View> baselineCards = new ConcurrentHashMap<>();
    private final DecisionReadCache decisions;
    private final BaselineEvidence evidence;
    private final BeforeSend before;
    private final DecisionWaits waits;
    /** docs/agent Agent중심-화면 AC-6: the day's share of live agent runs. */
    private final AgentRation ration;
    /** Inspector readings of closed analyses by request ID; a closed analysis's prompt does not change. */
    private final Map<String, List<CoreAdverseLabels.Reading>> adverseReadings = new ConcurrentHashMap<>();

    public LiveController(LiveRuns live, LiveGate gate, LiveQuota quota, LiveAllotment allotment,
                          TurnstileVerifier turnstile, ScenarioCatalog scenarios, VisitorCookies cookies,
                          ReplayViews views, WorkloadAdmin admin, TemplateCurrency templates,
                          BaselineEvidence evidence, BeforeSend before, DecisionWaits waits, ObjectMapper json,
                          AgentTaskCatalog agentTasks, AgentRation ration,
                          @Value("${showcase.live.agent-tasks:" + DEFAULT_AGENT_TASKS + "}") String agentTaskKeys,
                          @Value("${showcase.live.delegation-edit-case:" + DelegationChoice.EDITABLE_CASE + "}") String editableCase,
                          @Value("${showcase.live.burst-case:" + BurstChoice.BURST_CASE + "}") String burstCase) {
        this.ration = ration;
        this.agentTasks = agentTasks;
        this.agentTaskKeys = parseAgentTaskKeys(agentTaskKeys, agentTasks);
        // docs/agent AS-12: the case whose delegation a visitor edits is started by name though it is no entry of the list
        this.editableCase = editableCase.isBlank() ? null : editableCase.trim();
        if (this.editableCase != null && !DelegationChoice.EDITABLE_CASE.equals(this.editableCase)) {
            throw new IllegalStateException("Only the case " + DelegationChoice.EDITABLE_CASE + " has a delegation a visitor may edit");
        }
        if (this.editableCase != null) {
            agentTasks.find(this.editableCase).orElseThrow(() -> new IllegalStateException("Unknown editable case " + this.editableCase));
        }
        this.burstCase = burstCase.isBlank() ? null : burstCase.trim();
        if (this.burstCase != null && !BurstChoice.BURST_CASE.equals(this.burstCase)) {
            throw new IllegalStateException("Only the case " + BurstChoice.BURST_CASE + " has a burst a visitor may send");
        }
        if (this.burstCase != null) {
            agentTasks.find(this.burstCase).orElseThrow(() -> new IllegalStateException("Unknown burst case " + this.burstCase));
        }
        this.startableAgentKeys = startable(this.agentTaskKeys, this.editableCase, this.burstCase);
        this.views = views;
        this.waits = waits;
        this.evidence = evidence;
        this.before = before;
        this.admin = admin;
        this.decisions = new DecisionReadCache(admin::decision, Clock.systemUTC());
        this.templates = templates;
        this.json = json;
        this.live = live;
        this.gate = gate;
        this.quota = quota;
        this.allotment = allotment;
        this.turnstile = turnstile;
        this.scenarios = scenarios;
        this.cookies = cookies;
    }

    /**
     * docs/agent Agent중심-화면 AS-14: the agent cases open to visitors unless the settings say otherwise: the main case
     * (the delegation ended before the work), its normal pair (the same work inside the delegation), a request that names
     * a ticket the company does not have, an export to a destination the company does not list, and a delegation the
     * company has no record of. Each is short: no history of days before the work and a few requests.
     */
    static final String DEFAULT_AGENT_TASKS = "T5,N1,M14A,M22A,M10A";

    /** The most agent cases the settings may open: the day's share and the cap of agent runs are sized for a few. */
    static final int MOST_OPEN_AGENT_CASES = 8;

    /**
     * The agent cases a start may name: the open ones, then the case whose delegation a visitor may edit and the burst
     * case, which are started by name though they are no entry of the list.
     */
    static List<String> startable(List<String> open, String editableCase, String burstCase) {
        List<String> startable = new ArrayList<>(open);
        for (String extra : new String[]{editableCase, burstCase}) {
            if (extra != null && !startable.contains(extra)) {
                startable.add(extra);
            }
        }
        return List.copyOf(startable);
    }

    /**
     * The case a visitor's start runs: the named case with the visitor's choices applied to a copy. The delegation is
     * taken by the editable case only; the number of requests by the burst case only, and the burst case runs live only
     * with it (a visitor never runs the stored measurement's sixty).
     *
     * @throws IllegalArgumentException for a choice the case does not take or a value outside the lists
     */
    static ScenarioDefinition chosen(ScenarioDefinition scenario, DelegationChoice delegation, Integer copies) {
        ScenarioDefinition result = scenario;
        if (delegation != null && !delegation.isEmpty()) {
            result = delegation.applyTo(result);
        }
        if (BurstChoice.isBurst(result) && copies == null) {
            throw new IllegalArgumentException("A live burst needs the number of its requests");
        }
        return BurstChoice.apply(result, copies);
    }

    /** The keys of the open agent cases from the settings; unknown keys and more than eight are refused at start. */
    static List<String> parseAgentTaskKeys(String configured, AgentTaskCatalog catalog) {
        List<String> keys = Arrays.stream(configured.split(",")).map(String::trim).filter(key -> !key.isEmpty()).toList();
        if (keys.size() > MOST_OPEN_AGENT_CASES) {
            throw new IllegalStateException("At most " + MOST_OPEN_AGENT_CASES + " agent cases may be open to visitors, "
                    + keys.size() + " are configured");
        }
        keys.forEach(key -> catalog.find(key)
                .orElseThrow(() -> new IllegalStateException("Unknown live agent task " + key)));
        return keys;
    }

    /**
     * The definition a visitor's start names: a person scenario the live settings list, or an open agent case; nothing
     * for any other key, however the catalog holds it.
     */
    static ScenarioDefinition resolve(String key, List<String> scenarioKeys, ScenarioCatalog scenarios,
                                      List<String> agentTaskKeys, AgentTaskCatalog agentTasks) {
        if (scenarioKeys.contains(key)) {
            return scenarios.find(key).orElse(null);
        }
        return agentTaskKeys.contains(key) ? agentTasks.find(key).orElse(null) : null;
    }

    /** The agent cases the live settings open, as options whose subject is AGENT. */
    static List<ScenarioOption> openAgentCases(AgentTaskCatalog catalog, List<String> keys) {
        return keys.stream().map(key -> catalog.find(key).orElseThrow()).map(ScenarioOption::of).toList();
    }

    @GetMapping("/api/live/config")
    public Map<String, Object> config(HttpServletRequest request) {
        List<ScenarioOption> options = live.settings().scenarioKeys().stream()
                .map(key -> scenarios.find(key).orElseThrow())
                .map(ScenarioOption::of)
                .toList();
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("scenarios", options);
        // docs/agent Agent중심-화면 AS-6: the agent cases a visitor can run live, apart from the scenarios
        config.put("agentCases", openAgentCases(agentTasks, agentTaskKeys));
        // docs/agent AS-12: the case whose delegation a visitor may edit and the values a visitor may choose
        if (editableCase != null) {
            config.put("delegationEdit",
                    DelegationChoice.describe(editableCase, agentTasks.find(editableCase).orElseThrow().title()));
        }
        // docs/agent AS-13: the case a visitor may send a burst of live, the most requests live and the stored measurement's
        if (burstCase != null) {
            ScenarioDefinition burst = agentTasks.find(burstCase).orElseThrow();
            Map<String, Object> burstConfig = new LinkedHashMap<>();
            burstConfig.put("case", burstCase);
            burstConfig.put("title", burst.title());
            burstConfig.put("most", BurstChoice.LIVE_MOST);
            burstConfig.put("measured", burst.task().parallel().get(0).copies());
            burstConfig.put("points", quota.weights().burst());
            config.put("burst", burstConfig);
        }
        config.put("turnstileSiteKey", turnstile.siteKey());
        config.put("dailyRuns", quota.visitorDaily());
        config.put("remainingToday", visitor(request).map(quota::remaining).orElse(quota.visitorDaily()));
        // docs/agent Agent중심-화면 AC-2: the points an agent run costs and the agent runs left today
        config.put("agentRunPoints", quota.weights().agent());
        config.put("dailyAgentRuns", quota.agentDaily());
        config.put("remainingAgentToday", visitor(request).map(quota::remainingAgentRuns)
                .orElse(Math.min(quota.agentDaily(), quota.visitorDaily() / Math.max(1, quota.weights().agent()))));
        // docs/agent Agent중심-화면 AC-6: the day's share of live agent runs and the cap of agent runs at once
        config.put("liveTicketsLeft", ration.ticketsLeft());
        config.put("agentConcurrent", live.settings().agentConcurrent());
        config.put("agentRunsActive", live.agentRunsActive());
        config.put("paused", allotment.state().exhausted() || !live.hasRoom());
        return config;
    }

    @PostMapping("/api/live/runs")
    public ResponseEntity<Object> start(HttpServletRequest request, @RequestBody StartRequest start) {
        Optional<String> visitor = visitor(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (start == null || start.scenario() == null) {
            return ResponseEntity.badRequest().build();
        }
        ScenarioDefinition scenario = resolve(start.scenario(), live.settings().scenarioKeys(), scenarios,
                startableAgentKeys, agentTasks);
        if (scenario == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            // docs/agent AS-12, AS-13: a copy of the case with the visitor's choices: one change of the editable case's
            // delegation, or the number of requests (up to ten) of the burst case
            scenario = chosen(scenario, start.delegation(), start.copies());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
        try {
            return respond(gate.scenario(visitor.get(), request.getRemoteAddr(), scenario, start.turnstileToken()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("reason", "ENGINE_UNAVAILABLE"));
        }
    }

    /**
     * A body the server cannot read (not JSON, a value outside the lists of the delegation choice, a number of requests
     * that is no number) is refused with 400 like every other refusal of a start. Left to the container it would be
     * sent to the error page, which the visitor port does not open, and answer 403 (docs/agent Agent중심-화면 AS-12,
     * AS-13: the server refuses a value outside the lists with 400).
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Void> unreadable() {
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/api/live/combinations")
    public ResponseEntity<Object> combination(HttpServletRequest request, @RequestBody CombinationRequest body) {
        Optional<String> visitor = visitor(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Combination cell;
        try {
            cell = Combination.parse(body == null ? null : body.key());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
        try {
            return respond(gate.combination(visitor.get(), request.getRemoteAddr(), cell, body.turnstileToken()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("reason", "ENGINE_UNAVAILABLE"));
        }
    }

    @GetMapping("/api/live/runs/current")
    public ResponseEntity<LiveRun.View> current(HttpServletRequest request) {
        return act(request, run -> {
        });
    }

    @PostMapping("/api/live/runs/current/code")
    public ResponseEntity<LiveRun.View> requestCode(HttpServletRequest request) {
        return act(request, LiveRun::requestCode);
    }

    @PostMapping("/api/live/runs/current/answer")
    public ResponseEntity<LiveRun.View> answer(HttpServletRequest request, @RequestBody AnswerRequest answer) {
        return act(request, run -> run.answer(answer == null ? null : answer.code()));
    }

    @PostMapping("/api/live/runs/current/cancel")
    public ResponseEntity<LiveRun.View> cancel(HttpServletRequest request) {
        return act(request, LiveRun::cancel);
    }

    /** Gives up the additional check at once: the request stays held (the attacker has no access to the mailbox). */
    @PostMapping("/api/live/runs/current/abandon")
    public ResponseEntity<LiveRun.View> abandon(HttpServletRequest request) {
        return act(request, LiveRun::abandon);
    }

    /** Starts the identity check of the account control D blocked (ADR-33): a one-time code goes out. */
    @PostMapping("/api/live/runs/current/release-start")
    public ResponseEntity<LiveRun.View> releaseStart(HttpServletRequest request) {
        return act(request, LiveRun::startRelease);
    }

    /** Files the release request with the visitor's reason, after the identity check passed. */
    @PostMapping("/api/live/runs/current/release-request")
    public ResponseEntity<LiveRun.View> releaseRequest(HttpServletRequest request, @RequestBody ReleaseRequest body) {
        return act(request, run -> run.requestRelease(body == null ? null : body.reason()));
    }

    /** Approves the filed release request as the run's security administrator. */
    @PostMapping("/api/live/runs/current/release-approve")
    public ResponseEntity<LiveRun.View> releaseApprove(HttpServletRequest request) {
        return act(request, LiveRun::approve);
    }

    /**
     * docs/agent A7-3: approves or rejects, as the delegating employee, the request control D asked the employee to
     * confirm; the agent then sends it again with the confirmation.
     */
    @PostMapping("/api/live/runs/current/agent-confirmation")
    public ResponseEntity<LiveRun.View> agentConfirmation(HttpServletRequest request,
                                                          @RequestBody AgentConfirmationAnswer body) {
        return act(request, run -> run.decideAgentConfirmation(body != null && body.approve()));
    }

    /** Sends the step the visitor's run waits for the visitor to send (the attacker trying again). */
    @PostMapping("/api/live/runs/current/next")
    public ResponseEntity<LiveRun.View> next(HttpServletRequest request) {
        return act(request, LiveRun::proceed);
    }

    /**
     * The full result of a step of the visitor's own run once it completed, with each control's evidence and the
     * engine's reasoning (the same view as a recording); 409 while it runs or after a failure, 404 for a step the run
     * did not send.
     */
    @GetMapping("/api/live/runs/current/result")
    public ResponseEntity<ReplayView.StepResult> result(HttpServletRequest request,
                                                        @RequestParam(name = "step", defaultValue = "1") int step) {
        Optional<LiveRun> run = visitor(request).flatMap(live::current);
        if (run.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Optional<String> runId = run.get().completedRunId();
        if (runId.isEmpty()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
        boolean sent = run.get().view().steps().stream().anyMatch(view -> view.stepNo() == step);
        if (!sent) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(views.step(runId.get(), step));
    }

    /**
     * One stage of the engine's analysis of the visitor's own run, timed from the moment control D received the
     * request, both on D's clock (fabricated-data survey #44): context collected, first and second layer, decision
     * applied, error. Null when D no longer holds its receipt.
     */
    public record AnalysisStage(String type, Long atMs, String action, String layer, Double riskScore,
                                Double confidence, Long elapsedMs, String mitre) {
    }

    /**
     * Control D's decision of the step once the engine closed its analysis (a terminal event), before the run ends,
     * so the verdict and its reason show while a challenge or the other steps still wait (work 7 of
     * docs/showcase/화면설계서-v2-구현계획.md). Every value is the engine's own record.
     *
     * @param applied       BEFORE_RESPONSE or NEXT_REQUEST, as control D applies decisions of the operation
     * @param reason        the engine's reason, with the code of the contract's fixed sentence when it is one
     * @param adverseLabels the labels the core's response inspector reads as adverse evidence, read from the prompt
     *                      control D sent ({@link CoreAdverseLabels}); empty when D no longer holds the call; of a v20
     *                      decision the conditions the facts it sealed state (N-DEP-2)
     */
    public record LiveDecision(String finalAction, String proposedAction, boolean unresolved, Double riskScore,
                               Double confidence, String applied, ReplayView.EngineReason reason,
                               List<CoreAdverseLabels.Reading> adverseLabels, Long totalAnalysisMs, int modelCalls,
                               long promptTokens, long completionTokens) {

        /** How many of the inspector's adverse conditions the prompt met, counted here (T-27). */
        @JsonProperty("adverseMet")
        public long adverseMet() {
            return adverseLabels == null ? 0 : adverseLabels.stream().filter(CoreAdverseLabels.Reading::met).count();
        }

        /** How many adverse conditions the inspector checks (the core's list), counted here. */
        @JsonProperty("adverseChecked")
        public int adverseChecked() {
            return adverseLabels == null ? 0 : adverseLabels.size();
        }
    }

    /**
     * @param decision     null until the engine closed the analysis or when it made no decision record
     * @param decisionWait while the decision is still coming, how long the same case and step took in the current
     *                     measurement and about how long is left ({@link DecisionWaits}); null once it came or
     *                     without a measured decision
     */
    public record AnalysisView(int stepNo, List<AnalysisStage> stages, LiveDecision decision,
                               DecisionWaits.Wait decisionWait) {
    }

    /**
     * The engine's analysis of the visitor's own current run as it happens (deck p.12), read by the request ID of
     * control D's request of the step, or of its latest request without one; 404 before that request was sent, 503
     * when the engine cannot be read.
     */
    @GetMapping("/api/live/runs/current/analysis")
    public ResponseEntity<AnalysisView> analysis(HttpServletRequest request,
                                                 @RequestParam(name = "step", required = false) Integer step) {
        Optional<LiveRun> run = visitor(request).flatMap(live::current);
        Optional<LiveRun.EngineRequest> sent = run.flatMap(current -> current.engineRequest(step));
        if (sent.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        JsonNode evidence;
        try {
            evidence = decisions.get(sent.get().requestId());
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        List<AnalysisStage> stages = new ArrayList<>();
        Instant received = evidence.hasNonNull("receivedAt") ? Instant.parse(evidence.path("receivedAt").asText())
                : null;
        for (JsonNode event : evidence.path("events")) {
            Long atMs = null;
            if (received != null && event.hasNonNull("observedAt")) {
                atMs = Duration.between(received, Instant.parse(event.path("observedAt").asText())).toMillis();
            }
            stages.add(new AnalysisStage(event.path("type").asText(), atMs, textOrNull(event, "action"),
                    textOrNull(event, "layer"), doubleOrNull(event, "riskScore"), doubleOrNull(event, "confidence"),
                    event.hasNonNull("elapsedMs") ? event.path("elapsedMs").asLong() : null,
                    textOrNull(event, "mitre")));
        }
        LiveDecision decision;
        try {
            decision = decision(sent.get(), evidence);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        DecisionWaits.Wait decisionWait = decision != null ? null
                : waits.estimate(run.get().scenario(), sent.get().stepNo(), sent.get().sentAt()).orElse(null);
        return ResponseEntity.ok(new AnalysisView(sent.get().stepNo(), stages, decision, decisionWait));
    }

    private LiveDecision decision(LiveRun.EngineRequest sent, JsonNode evidence) throws IOException {
        if (!DecisionReadCache.ended(evidence)) {
            return null;
        }
        EngineDecision engine = EngineDecision.from(evidence, EngineDecision.synchronous(sent.operation()));
        if (engine == null || engine.finalAction() == null) {
            return null;
        }
        // N-DEP-2: a v20 decision's adverse conditions are read from the facts it sealed, not from its prompt's labels.
        List<CoreAdverseLabels.Reading> sealed = CoreAdverseLabels.sealed(
                SealedDeviations.metadata(engine.raw(), json));
        return new LiveDecision(engine.finalAction(), engine.proposedAction(), engine.unresolved(),
                engine.riskScore(), engine.confidence(), engine.applied(), views.engineReason(engine),
                sealed != null ? sealed : adverseReadings(sent.requestId()), engine.totalAnalysisMs(),
                engine.modelCalls(), engine.promptTokens(), engine.completionTokens());
    }

    /** The inspector's reading of the last model call's prompt, as the anatomy reads the stored copy. */
    private List<CoreAdverseLabels.Reading> adverseReadings(String requestId) throws IOException {
        List<CoreAdverseLabels.Reading> kept = adverseReadings.get(requestId);
        if (kept != null) {
            return kept;
        }
        JsonNode last = null;
        for (JsonNode call : admin.exchanges(requestId)) {
            if (last == null || call.path("callNo").asInt() > last.path("callNo").asInt()) {
                last = call;
            }
        }
        if (last == null) {
            return List.of();
        }
        List<CoreAdverseLabels.Reading> readings = CoreAdverseLabels.read(
                last.path("systemPrompt").asText("") + "\n" + last.path("userPrompt").asText(""));
        if (adverseReadings.size() >= DecisionReadCache.MAX_ENTRIES) {
            adverseReadings.clear();
        }
        adverseReadings.put(requestId, readings);
        return readings;
    }

    /**
     * What the engine received for a live case in its latest real run from the current template, shown before the
     * visitor sends it (e1-compare, work 8); the comparison is null when no such run exists, 404 for a case the live
     * runs do not offer.
     */
    @GetMapping("/api/live/before/{scenario}")
    public ResponseEntity<BeforeSend.Before> before(@PathVariable("scenario") String scenario,
                                                    @RequestParam(name = "step", defaultValue = "1") int step) {
        if (!live.settings().scenarioKeys().contains(scenario)) {
            return ResponseEntity.notFound().build();
        }
        try {
            return ResponseEntity.ok(before.latest(scenarios.find(scenario).orElseThrow(), step));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }

    /**
     * What the engine received in one stored step (the decision details' "received" tab, 7.7), as the same view as the
     * comparison before sending; 404 when the run, the step or its anatomy is unknown.
     */
    @GetMapping("/api/runs/{runId}/steps/{stepNo}/received")
    public ResponseEntity<BeforeSend.View> received(@PathVariable("runId") String runId,
                                                    @PathVariable("stepNo") int stepNo) {
        return before.received(runId, stepNo).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    /**
     * What Contexa knows about a protagonist: the engine baseline of the template its run principals are cloned from
     * and the work that taught it. Only protagonists have templates (the business database scripts their work), so
     * anyone else is 404, as is a protagonist before a current template exists.
     */
    @GetMapping("/api/live/baseline/{employee}")
    public ResponseEntity<BaselineCard.View> baseline(@PathVariable("employee") String employee) {
        if (!EMPLOYEE_KEY.matcher(employee).matches()) {
            return ResponseEntity.notFound().build();
        }
        try {
            Optional<TemplateStore.ReadyTemplate> template = templates.current(employee);
            if (template.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            String templateId = template.get().templateId();
            BaselineCard.View card = baselineCards.get(templateId);
            if (card == null) {
                JsonNode profile = admin.employee(employee);
                card = BaselineCard.of(templateId, template.get().snapshot(), profile,
                        evidence.requests(templateId, profile), json);
                baselineCards.put(templateId, card);
            }
            return ResponseEntity.ok(card.withHours(evidence.hours(templateId).orElse(null)));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.path(field).asText() : null;
    }

    private static Double doubleOrNull(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.path(field).asDouble() : null;
    }

    /** The HTTP status of a reason the gate refuses a start for; every limit of a visitor is "too many requests". */
    static HttpStatus statusOf(String reason) {
        return switch (reason) {
            case "VISITOR_LIMIT", "ADDRESS_LIMIT", "AGENT_LIMIT" -> HttpStatus.TOO_MANY_REQUESTS;
            case "ALLOTMENT", "TEMPLATE" -> HttpStatus.SERVICE_UNAVAILABLE;
            case "BUSY", "AGENT_BUSY" -> HttpStatus.CONFLICT;
            default -> HttpStatus.FORBIDDEN;
        };
    }

    private ResponseEntity<Object> respond(LiveGate.Outcome outcome) {
        if (outcome instanceof LiveGate.Started started) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(started.run().view());
        }
        LiveGate.Refused refused = (LiveGate.Refused) outcome;
        String reason = refused.reason();
        HttpStatus status = statusOf(reason);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason);
        if (refused.fallback() != null) {
            body.put("fallback", refused.fallback());
        }
        return ResponseEntity.status(status).body(body);
    }

    private ResponseEntity<LiveRun.View> act(HttpServletRequest request, Consumer<LiveRun> action) {
        Optional<LiveRun> run = visitor(request).flatMap(live::current);
        if (run.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        action.accept(run.get());
        return ResponseEntity.ok(run.get().view());
    }

    private Optional<String> visitor(HttpServletRequest request) {
        Cookie[] all = request.getCookies();
        if (all == null) {
            return Optional.empty();
        }
        for (Cookie cookie : all) {
            if (VisitorCookies.NAME.equals(cookie.getName())) {
                return cookies.verify(cookie.getValue()).map(VisitorCookies::hash);
            }
        }
        return Optional.empty();
    }
}
