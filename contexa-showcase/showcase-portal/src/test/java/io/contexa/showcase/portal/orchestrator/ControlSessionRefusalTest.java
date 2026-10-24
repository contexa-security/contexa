package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent DD-27: control D's call limit for agents (A5-7) answers 429 with its code and the seconds to wait; the
 * run reads it as a refusal with its rule, as it reads the engine's 401, 403 and 423. Other answers stay as they were.
 */
class ControlSessionRefusalTest {

    private static final Instant AT = Instant.parse("2026-09-30T14:20:00Z");
    private static final String PATH = "/api/projects/HX-310/documents";

    private HttpServer server;
    private volatile int status;
    private volatile String body;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] answer = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, answer.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(answer);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void theCallLimitsAnswerIsARefusalWithItsRuleAndTheSecondsToWait() throws Exception {
        status = 429;
        body = "{\"status\":429,\"error\":\"AGENT_CALL_LIMIT\",\"message\":\"The agent passed its call limit; slow "
                + "down\",\"scope\":\"DELEGATION\",\"limit\":120,\"retryAfterSeconds\":37}";

        ControlSession.StepOutcome outcome = session().send(BusinessOperation.DOCUMENT_LIST, PATH, AT);

        assertThat(outcome.outcome()).isEqualTo("REFUSED");
        assertThat(outcome.ruleId()).isEqualTo("AGENT_CALL_LIMIT");
        assertThat(outcome.reason()).isEqualTo("The agent passed its call limit; slow down");
        assertThat(outcome.deliveredItems()).isZero();
        assertThat(AgentRetryStorm.limited(outcome)).isTrue();
        assertThat(AgentRetryStorm.retryAfterSeconds(outcome)).isEqualTo(37);
    }

    @Test
    void aServerErrorStaysAnError() throws Exception {
        status = 500;
        body = "{\"error\":\"INTERNAL\"}";

        ControlSession.StepOutcome outcome = session().send(BusinessOperation.DOCUMENT_LIST, PATH, AT);

        assertThat(outcome.outcome()).isEqualTo("ERROR");
        assertThat(outcome.ruleId()).isNull();
    }

    private ControlSession session() {
        WorkloadClient client = new WorkloadClient(URI.create("http://" + server.getAddress().getHostString() + ":"
                + server.getAddress().getPort()), new InternalContextSigner(randomKey()),
                new WorkloadClient.RunIdentity("run-aabbccddeeff", "org-aabbccddeeff", "tenant-aabbccddeeff",
                        "10.60.1.200", "report-agent/1.0"), Duration.ofSeconds(10));
        return new ControlSession(Control.D, client, new ObjectMapper().findAndRegisterModules());
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
