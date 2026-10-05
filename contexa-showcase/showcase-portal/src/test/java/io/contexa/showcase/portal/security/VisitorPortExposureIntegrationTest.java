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
    private enum Reach { READ, VISITOR_WRITE, GATED_ENGINE_START, OWN_RUN_STEP }

    private static final Map<String, Reach> VISITOR_PATHS = new TreeMap<>(Map.ofEntries(
            Map.entry("GET /api/visitor", Reach.READ),
            Map.entry("POST /api/predictions", Reach.VISITOR_WRITE),
            Map.entry("GET /api/contract", Reach.READ),
            Map.entry("GET /api/pairs", Reach.READ),
            Map.entry("GET /api/replays/{pairKey}", Reach.READ),
            Map.entry("GET /api/specs/{specHash}", Reach.READ),
            Map.entry("GET /api/combinations", Reach.READ),
            Map.entry("GET /api/combinations/{key}", Reach.READ),
            Map.entry("GET /api/live/config", Reach.READ),
            Map.entry("GET /api/live/runs/current", Reach.READ),
            Map.entry("POST /api/live/runs", Reach.GATED_ENGINE_START),
            Map.entry("POST /api/live/combinations", Reach.GATED_ENGINE_START),
            // A started run's own steps: the code request and the answer continue the run the gate admitted, at most
            // LiveRun.MAX_ATTEMPTS times; cancel only ends it.
            Map.entry("POST /api/live/runs/current/code", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/answer", Reach.OWN_RUN_STEP),
            Map.entry("POST /api/live/runs/current/cancel", Reach.OWN_RUN_STEP)));

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
                .map(Map.Entry::getKey)).containsExactlyInAnyOrder("POST /api/live/runs", "POST /api/live/combinations");
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
