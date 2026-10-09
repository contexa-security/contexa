package io.contexa.showcase.portal.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

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
        "showcase.portal.controls.d=http://127.0.0.1:9/", "showcase.live.enabled=true"})
class VisitorPortExposureIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();
    private static final int OPS_PORT = freePort();

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
    }

    @Autowired
    TestRestTemplate http;

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    RequestMappingHandlerMapping mappings;

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
