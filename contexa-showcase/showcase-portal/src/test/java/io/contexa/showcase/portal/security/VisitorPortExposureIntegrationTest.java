package io.contexa.showcase.portal.security;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deck p.37 on a real portal server with every visitor feature on (live runs, combinations, operator port):
 * P5-SEC-03 every request path on the visitor port is on the allowlist below, and the only paths that start engine
 * work are the two gated live-run starts; P5-SEC-06 the operator API answers only on the operator port, errors carry
 * no internals and the actuator shows health only. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1",
        "showcase.portal.controls.a=http://127.0.0.1:9/", "showcase.portal.controls.b=http://127.0.0.1:9/",
        "showcase.portal.controls.c1=http://127.0.0.1:9/", "showcase.portal.controls.c2=http://127.0.0.1:9/",
        "showcase.live.enabled=true"})
class VisitorPortExposureIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();
    private static final int OPS_PORT = freePort();

    private static final String SESSION_ID = "0123456789ABCDEF0123456789ABCDEF";
    /** W7-13: control D's prompt facts of a seal whose session line and inspection name an HTTP session ID. */
    private static final String PROMPT_FACTS = """
            {"packageId": "pkg-1", "requestId": "req-1", "capturedAt": "2026-10-16T03:17:20Z",
             "packageHash": "sha256:abc", "promptBundleVersion": "2026.10.16-v20.22", "promptBundleHash": "c6b5",
             "promptBundleSelectionSource": "CONFIGURATION", "userPromptLayoutVersion": "v20-dictionary-blocks",
             "reasonCodes": [{"code": "DEVIATION_TIME", "fact": "F1"}],
             "lines": [{"number": 8, "block": "SESSION", "factId": "S1", "label": "LoginMethod",
                        "value": "PASSWORD (session %1$s)", "grades": ["HOST"]}],
             "inspection": {"verdict": "FAIL", "inspectorVersion": "prompt-inspector/17",
                            "inspectedAt": "2026-10-16T03:18:00Z",
                            "checks": [{"code": "FACT_ACCURACY", "matched": 0, "mismatched": 1, "unverifiable": 0,
                                        "mismatches": [{"line": 8, "actual": "PASSWORD (session %1$s)"}]}]}}"""
            .formatted(SESSION_ID);
    /** W7-13: control D as far as the sealed prompt views read it; started with the context, stopped after. */
    private static HttpServer controlD;

    /** What each visitor path may do; a new endpoint fails this test until it is placed here. */
    /** COMPUTE: computes an answer from stored records only; it writes nothing and starts no engine work. */
    private enum Reach { READ, COMPUTE, VISITOR_WRITE, GATED_ENGINE_START, OWN_RUN_STEP }

    private static final Map<String, Reach> VISITOR_PATHS = new TreeMap<>(Map.ofEntries(
            Map.entry("GET /api/visitor", Reach.READ),
            Map.entry("POST /api/predictions", Reach.VISITOR_WRITE),
            Map.entry("POST /api/shares", Reach.VISITOR_WRITE),
            Map.entry("GET /api/results/{pairKey}", Reach.READ),
            Map.entry("GET /s/{key}", Reach.READ),
            Map.entry("GET /s/{key}/card.png", Reach.READ),
            Map.entry("GET /api/pairs", Reach.READ),
            Map.entry("GET /api/replays/{pairKey}", Reach.READ),
            Map.entry("GET /api/specs/{specHash}", Reach.READ),
            Map.entry("GET /api/combinations", Reach.READ),
            Map.entry("GET /api/combinations/{key}", Reach.READ),
            Map.entry("GET /api/stats", Reach.READ),
            Map.entry("GET /api/rules/cases", Reach.READ),
            // The demo's real settings of the five approaches and its retention periods (G3, adoption screen).
            Map.entry("GET /api/settings", Reach.READ),
            // The rules scene's settings: the rule classes decide the recorded cases again (H-10).
            Map.entry("POST /api/rules/evaluate", Reach.COMPUTE),
            // The designed cases as frozen, with their definition hashes and the rule controls' hash (W2-5).
            Map.entry("GET /api/cases", Reach.READ),
            // The first screen's replay of the two designated measured runs (work 17): stored records only.
            Map.entry("GET /api/hook", Reach.READ),
            // The visitor's own journey (work 14): place, differences seen, own calls, and own runs.
            Map.entry("GET /api/journey", Reach.READ),
            Map.entry("POST /api/journey", Reach.VISITOR_WRITE),
            Map.entry("GET /api/journey/act-end", Reach.READ),
            // The quiz (work 15): the questions without answers, and the server's scoring with anonymous counts.
            Map.entry("GET /api/quiz", Reach.READ),
            Map.entry("POST /api/quiz", Reach.VISITOR_WRITE),
            // The anonymous daily counts (ADR-35): no visitor in them.
            Map.entry("GET /api/tally", Reach.READ),
            // The verdict anatomy of a stored run step and its model call texts (docs/showcase/데모-재설계.md 5.3):
            // stored records only, HTTP session identifiers masked.
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/anatomy", Reach.READ),
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/exchanges", Reach.READ),
            // Where the engine input of a request differed from an earlier run's (lab-3), compared on the server.
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/input-changes", Reach.READ),
            Map.entry("GET /api/runs/{runId}/versus", Reach.READ),
            // The stored result of a step of any run, every approach side by side (5A.1 comparison, 5A.2 run list).
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/result", Reach.READ),
            // W7-13: a step's sealed prompt, the facts by block with their sources and the quality ribbon with the
            // bundle, seal and inspection, read from control D's record of the seal; HTTP session identifiers masked.
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/facts", Reach.READ),
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/quality", Reach.READ),
            // W7-13: the same step of the same case under the other prompt bundle, from recorded runs and their seals.
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/other-bundle", Reach.READ),
            // W7-13: what the one changed lab condition changed in the model's input, compared on the server.
            Map.entry("GET /api/lab/runs/{runId}/delta", Reach.COMPUTE),
            // W7-13: the prompt quality an operator published for a measurement setting: stored values only.
            Map.entry("GET /api/benchmark/prompt-quality", Reach.READ),
            // The benchmark of a measurement setting, counted from stored protocol runs (5A.2, W5).
            Map.entry("GET /api/benchmark", Reach.READ),
            // The counted protocol runs of a setting with their scores: the benchmark's raw data (S10).
            Map.entry("GET /api/benchmark/runs", Reach.READ),
            // Other visitors' assessments of the same request, after the benchmark's delay (5A.1, W4-2).
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/peer-assessments", Reach.READ),
            // The score of a stored run by the one scoring rule (5.0).
            Map.entry("GET /api/runs/{runId}/score", Reach.READ),
            Map.entry("GET /api/live/config", Reach.READ),
            Map.entry("GET /api/live/runs/current", Reach.READ),
            Map.entry("GET /api/live/runs/current/result", Reach.READ),
            Map.entry("GET /api/live/runs/current/analysis", Reach.READ),
            Map.entry("GET /api/live/baseline/{employee}", Reach.READ),
            // The comparison before sending (work 8 of docs/showcase/화면설계서-v2-구현계획.md): the engine input of
            // the latest stored run of the same definition, read from its anatomy; nothing is sent to an engine.
            Map.entry("GET /api/live/before/{scenario}", Reach.READ),
            // The same view for one stored step (the decision details' "received" tab, 7.7), read from its anatomy.
            Map.entry("GET /api/runs/{runId}/steps/{stepNo}/received", Reach.READ),
            // The teaser cards' measured values and the facts the screens' sentences rest on (work 19).
            Map.entry("GET /api/teasers", Reach.READ),
            // A case's runs in the current measurement and what each decision does next, both read from records.
            Map.entry("GET /api/cases/{key}/measured", Reach.READ),
            Map.entry("GET /api/engine/actions", Reach.READ),
            Map.entry("POST /api/live/runs", Reach.GATED_ENGINE_START),
            Map.entry("POST /api/live/combinations", Reach.GATED_ENGINE_START),
            // The lab (docs/showcase/데모-재설계.md 5A.1): its choices, a composed case through the same cost gate, the
            // visitor's own recent lab runs, and an assessment of a decision only by the run's own visitor, once.
            Map.entry("GET /api/lab/options", Reach.READ),
            Map.entry("GET /api/lab/runs/recent", Reach.READ),
            Map.entry("POST /api/lab/runs", Reach.GATED_ENGINE_START),
            Map.entry("POST /api/lab/before", Reach.COMPUTE),
            Map.entry("POST /api/runs/{runId}/steps/{stepNo}/assessment", Reach.VISITOR_WRITE),
            // A started run's own steps: the code request and the answer continue the run the gate admitted, at most
            // LiveRun.MAX_ATTEMPTS times; next sends the one step the scenario leaves to the visitor, once; cancel
            // and abandon only end it.
            Map.entry("POST /api/live/runs/current/code", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/answer", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/next", Reach.OWN_RUN_STEP),
            // The release of a block (ADR-33): the run's own principal and the run's own approver act on the run's
            // own block only, once each, through the engine's endpoints.
            Map.entry("POST /api/live/runs/current/release-start", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/release-request", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/release-approve", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/cancel", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/abandon", Reach.OWN_RUN_STEP)));

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
        registry.add("showcase.portal.ops.port", () -> OPS_PORT);
        controlD = controlD();
        registry.add("showcase.portal.controls.d", () -> "http://127.0.0.1:" + controlD.getAddress().getPort() + "/");
    }

    @Autowired
    TestRestTemplate http;

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    RequestMappingHandlerMapping mappings;

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void everyVisitorPathIsOnTheAllowlistAndOnlyTheGatedStartsReachTheEngine() {
        Set<String> visitor = new TreeSet<>();
        Set<String> operator = new TreeSet<>();
        mappings.getHandlerMethods().keySet().forEach(info -> info.getPatternValues().forEach(pattern -> {
            Set<String> target = pattern.startsWith("/ops/") ? operator : visitor;
            info.getMethodsCondition().getMethods().forEach(method -> target.add(method + " " + pattern));
            if (info.getMethodsCondition().getMethods().isEmpty()) {
                target.add("ANY " + pattern);
            }
        }));
        visitor.remove("ANY /error");

        assertThat(visitor).containsExactlyInAnyOrderElementsOf(VISITOR_PATHS.keySet());
        assertThat(operator).isNotEmpty();
        assertThat(VISITOR_PATHS.entrySet().stream().filter(path -> path.getValue() == Reach.GATED_ENGINE_START)
                .map(Map.Entry::getKey)).containsExactlyInAnyOrder("POST /api/live/runs", "POST /api/live/combinations",
                        "POST /api/lab/runs");
    }

    @Test
    void theOperatorApiAnswersOnlyOnTheOperatorPort() {
        assertThat(http.getForEntity("/ops/recordings", String.class).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(http.getForEntity("/ops/engine", String.class).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        String ops = "http://127.0.0.1:" + OPS_PORT;
        assertThat(http.getForEntity(ops + "/ops/scenarios", String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
        ResponseEntity<String> live = http.getForEntity(ops + "/ops/live/status", String.class);
        assertThat(live.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(live.getBody()).contains("\"maxConcurrent\":50", "\"allotment\"", "\"refusalsThisHour\"");
        assertThat(http.getForEntity("/ops/live/status", String.class).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(http.getForEntity("/ops/teasers", String.class).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(http.getForEntity(ops + "/api/pairs", String.class).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(http.getForEntity(ops + "/actuator/health", String.class).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void errorsAndTheActuatorExposeNothingInternal() {
        for (String path : new String[]{"/api/not-a-real-endpoint", "/api/replays/..%2F..%2Fetc", "/api/specs/x'"}) {
            ResponseEntity<String> refused = http.getForEntity(path, String.class);
            assertThat(refused.getStatusCode().is4xxClientError()).as(path).isTrue();
            assertThat(String.valueOf(refused.getBody())).as(path)
                    .doesNotContain("trace", "Exception", "at io.", "showcase_portal", "jdbc:", "127.0.0.1:9", "SQL");
        }
        for (String path : new String[]{"/actuator/env", "/actuator/beans", "/actuator/configprops",
                "/actuator/mappings", "/actuator/heapdump", "/actuator/info"}) {
            assertThat(http.getForEntity(path, String.class).getStatusCode()).as(path)
                    .isIn(HttpStatus.NOT_FOUND, HttpStatus.FORBIDDEN, HttpStatus.UNAUTHORIZED);
        }
        assertThat(http.getForEntity("/actuator/health", String.class).getBody()).isEqualTo("{\"status\":\"UP\"}");
    }

    /**
     * W7-13 (C-14): the sealed prompt views answer on the visitor port from control D's record of the seal, and no
     * HTTP session identifier leaves the portal; the lab delta of a run that is not a lab run and the prompt quality
     * before any publication are not found.
     */
    @Test
    void theSealedPromptViewsAnswerWithoutAnHttpSessionIdentifier() {
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status)
                values (?, 'A3', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), 'COMPLETED')""",
                runId, "v" + runId);
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, unresolved, applied, records,
                    events)
                values (?, ?, 1, 'CHALLENGE', false, 'BEFORE_RESPONSE', '[]'::jsonb, '[]'::jsonb)""",
                UUID.randomUUID(), runId);

        for (String view : new String[]{"facts", "quality"}) {
            ResponseEntity<String> answer = http.getForEntity("/api/runs/" + runId + "/steps/1/" + view, String.class);
            assertThat(answer.getStatusCode()).as(view).isEqualTo(HttpStatus.OK);
            assertThat(answer.getBody()).as(view).contains("\"available\":true", "<SESSION>")
                    .doesNotContain(SESSION_ID);
        }
        assertThat(http.getForEntity("/api/lab/runs/" + runId + "/delta", String.class).getStatusCode())
                .as("not a lab run").isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(http.getForEntity("/api/benchmark/prompt-quality", String.class).getStatusCode())
                .as("nothing published").isEqualTo(HttpStatus.NOT_FOUND);
    }

    /**
     * W7-13 (C-14): the prompt modal's comparison answers on the visitor port with the same definition's step under
     * the other bundle, the texts as the portal stored them, and no HTTP session identifier leaves the portal.
     */
    @Test
    void theOtherBundleViewAnswersWithoutAnHttpSessionIdentifier() {
        String sha = "d".repeat(64);
        String now = storedRun(sha, spec("2026.10.16-v20.22"), Instant.parse("2026-10-16T03:00:00Z"));
        String before = storedRun(sha, spec("2026.10.11-v19.8"), Instant.parse("2026-10-11T03:00:00Z"));

        ResponseEntity<String> answer = http.getForEntity("/api/runs/" + now + "/steps/1/other-bundle", String.class);

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(answer.getBody()).contains("\"available\":true", "\"runId\":\"" + before + "\"", "<SESSION>")
                .doesNotContain(SESSION_ID);
    }

    /** An execution specification naming the bundle; its hash. */
    private String spec(String bundle) {
        String specHash = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        jdbc.update("""
                insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode,
                    endpoint_protection, chat_model, embedding_model, embedding_dimensions, prompt_hash, rule_version,
                    time_zone, prompt_bundle)
                values (?, ?, 'c', 'e', 'ENFORCE', '{}'::jsonb, 'm', 'em', 1024, ?, ?, 'UTC', ?)""",
                UUID.randomUUID(), specHash, "b".repeat(64), "c".repeat(64), bundle);
        return specHash;
    }

    /** A completed run of case A3 with one decision and its stored model call, whose user prompt names a session. */
    private String storedRun(String sha, String specHash, Instant startedAt) {
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        UUID requestId = UUID.randomUUID();
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, spec_hash, scenario_sha256, started_at)
                values (?, 'A3', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), 'COMPLETED', ?, ?,
                    ?)""", runId, "v" + runId, specHash, sha, Timestamp.from(startedAt));
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, unresolved, applied, records,
                    events)
                values (?, ?, 1, 'CHALLENGE', false, 'BEFORE_RESPONSE', '[]'::jsonb, '[]'::jsonb)""",
                requestId, runId);
        jdbc.update("""
                insert into run_model_exchange (request_id, call_no, run_id, step_no, user_prompt, success)
                values (?, 1, ?, 1, ?, true)""", requestId, runId, "=== SESSION ===\nSessionId: " + SESSION_ID + "\n");
        return runId;
    }

    @AfterAll
    static void stopControlD() {
        if (controlD != null) {
            controlD.stop(0);
        }
    }

    /** Control D's internal API as far as the sealed prompt views read it; every other path is not found. */
    private static HttpServer controlD() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/internal/decisions/", exchange -> {
                boolean facts = exchange.getRequestURI().getPath().endsWith("/prompt-facts");
                byte[] body = (facts ? PROMPT_FACTS : "{}").getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(facts ? 200 : 404, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
