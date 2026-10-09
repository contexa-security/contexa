package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.anatomy.BeforeSend;
import io.contexa.showcase.portal.anatomy.CoreAdverseLabels;
import io.contexa.showcase.portal.combination.Combination;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.EngineDecision;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    public record ScenarioOption(String key, Map<String, String> title, String classification) {
    }

    public record StartRequest(String scenario, String turnstileToken) {
    }

    public record CombinationRequest(String key, String turnstileToken) {
    }

    public record AnswerRequest(String code) {
    }

    public record ReleaseRequest(String reason) {
    }

    private final LiveRuns live;
    private final LiveGate gate;
    private final LiveQuota quota;
    private final LiveAllotment allotment;
    private final TurnstileVerifier turnstile;
    private final ScenarioCatalog scenarios;
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
    /** Inspector readings of closed analyses by request ID; a closed analysis's prompt does not change. */
    private final Map<String, List<CoreAdverseLabels.Reading>> adverseReadings = new ConcurrentHashMap<>();

    public LiveController(LiveRuns live, LiveGate gate, LiveQuota quota, LiveAllotment allotment,
                          TurnstileVerifier turnstile, ScenarioCatalog scenarios, VisitorCookies cookies,
                          ReplayViews views, WorkloadAdmin admin, TemplateCurrency templates,
                          BaselineEvidence evidence, BeforeSend before, DecisionWaits waits, ObjectMapper json) {
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

    @GetMapping("/api/live/config")
    public Map<String, Object> config(HttpServletRequest request) {
        List<ScenarioOption> options = live.settings().scenarioKeys().stream()
                .map(key -> scenarios.find(key).orElseThrow())
                .map(scenario -> new ScenarioOption(scenario.key(), scenario.title(),
                        scenario.oracle().classification()))
                .toList();
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("scenarios", options);
        config.put("turnstileSiteKey", turnstile.siteKey());
        config.put("dailyRuns", quota.visitorDaily());
        config.put("remainingToday", visitor(request).map(quota::remaining).orElse(quota.visitorDaily()));
        config.put("paused", allotment.state().exhausted() || !live.hasRoom());
        return config;
    }

    @PostMapping("/api/live/runs")
    public ResponseEntity<Object> start(HttpServletRequest request, @RequestBody StartRequest start) {
        Optional<String> visitor = visitor(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (start == null || start.scenario() == null || !live.settings().scenarioKeys().contains(start.scenario())) {
            return ResponseEntity.badRequest().build();
        }
        ScenarioDefinition scenario = scenarios.find(start.scenario()).orElse(null);
        if (scenario == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            return respond(gate.scenario(visitor.get(), request.getRemoteAddr(), scenario, start.turnstileToken()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("reason", "ENGINE_UNAVAILABLE"));
        }
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
     *                      control D sent ({@link CoreAdverseLabels}); empty when D no longer holds the call
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
        return new LiveDecision(engine.finalAction(), engine.proposedAction(), engine.unresolved(),
                engine.riskScore(), engine.confidence(), engine.applied(), views.engineReason(engine),
                adverseReadings(sent.requestId()), engine.totalAnalysisMs(), engine.modelCalls(),
                engine.promptTokens(), engine.completionTokens());
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

    private ResponseEntity<Object> respond(LiveGate.Outcome outcome) {
        if (outcome instanceof LiveGate.Started started) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(started.run().view());
        }
        LiveGate.Refused refused = (LiveGate.Refused) outcome;
        String reason = refused.reason();
        HttpStatus status = switch (reason) {
            case "VISITOR_LIMIT", "ADDRESS_LIMIT" -> HttpStatus.TOO_MANY_REQUESTS;
            case "ALLOTMENT", "TEMPLATE" -> HttpStatus.SERVICE_UNAVAILABLE;
            case "BUSY" -> HttpStatus.CONFLICT;
            default -> HttpStatus.FORBIDDEN;
        };
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
