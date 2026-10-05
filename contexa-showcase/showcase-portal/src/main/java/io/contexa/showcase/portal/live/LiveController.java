package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Visitor API of live runs (deck p.12, p.13, docs/showcase/P4-설계.md). It exists only with
 * {@code showcase.live.enabled=true}; the visitor is the one of the signed visitor cookie, every change is a POST under
 * the CSRF token, and every new run passes the cost gate. The client address is the request's remote address, which a
 * production portal takes from its trusted proxy only.
 */
@RestController
@ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
public class LiveController {

    public record ScenarioOption(String key, Map<String, String> title, String classification) {
    }

    public record StartRequest(String scenario, String turnstileToken) {
    }

    public record CombinationRequest(String key, String turnstileToken) {
    }

    public record AnswerRequest(String code) {
    }

    private final LiveRuns live;
    private final LiveGate gate;
    private final LiveQuota quota;
    private final LiveAllotment allotment;
    private final TurnstileVerifier turnstile;
    private final ScenarioCatalog scenarios;
    private final VisitorCookies cookies;

    public LiveController(LiveRuns live, LiveGate gate, LiveQuota quota, LiveAllotment allotment,
                          TurnstileVerifier turnstile, ScenarioCatalog scenarios, VisitorCookies cookies) {
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

    private ResponseEntity<Object> respond(LiveGate.Outcome outcome) {
        if (outcome instanceof LiveGate.Recorded recorded) {
            return ResponseEntity.ok(Map.of("recorded", true, "combination", recorded.view()));
        }
        if (outcome instanceof LiveGate.Started started) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(started.run().view());
        }
        String reason = ((LiveGate.Refused) outcome).reason();
        HttpStatus status = switch (reason) {
            case "VISITOR_LIMIT", "ADDRESS_LIMIT" -> HttpStatus.TOO_MANY_REQUESTS;
            case "ALLOTMENT", "TEMPLATE" -> HttpStatus.SERVICE_UNAVAILABLE;
            case "BUSY" -> HttpStatus.CONFLICT;
            default -> HttpStatus.FORBIDDEN;
        };
        return ResponseEntity.status(status).body(Map.of("reason", reason));
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
