package io.contexa.showcase.business.client;

import com.sun.net.httpserver.HttpServer;
import io.contexa.showcase.business.internal.InternalContext;
import io.contexa.showcase.business.internal.InternalContextHeaders;
import io.contexa.showcase.business.internal.InternalContextSigner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * W7-4 (docs/showcase/프롬프트-최종-구현계획.md 8.7): a request carries the headers a requester adds, such as an
 * X-Request-ID of its own choice, beside the run's signed internal context, which keeps the request's own id; no added
 * header replaces a header of that context or the run's device.
 */
class WorkloadClientTest {

    private static final Instant AT = Instant.parse("2026-09-30T03:17:00Z");
    private static final String EXPORT = "/api/projects/GB-500/exports?items=4831";
    private static final WorkloadClient.RunIdentity RUN = new WorkloadClient.RunIdentity("run-aabbccddeeff",
            "org-aabbccddeeff", "tenant-aabbccddeeff", "10.40.12.77", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

    private final InternalContextSigner signer = new InternalContextSigner(randomKey());
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private HttpServer server;
    private WorkloadClient client;

    /** One request as the server received it, header names in lower case. */
    private record Seen(String method, String path, Map<String, String> headers, String body) {

        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            Map<String, String> headers = new HashMap<>();
            exchange.getRequestHeaders().forEach((name, values) ->
                    headers.put(name.toLowerCase(Locale.ROOT), values.get(0)));
            String body;
            try (InputStream in = exchange.getRequestBody()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            seen.add(new Seen(exchange.getRequestMethod(), exchange.getRequestURI().toString(), headers, body));
            byte[] answer = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, answer.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(answer);
            }
        });
        server.start();
        client = new WorkloadClient(URI.create("http://" + server.getAddress().getHostString() + ":"
                + server.getAddress().getPort()), signer, RUN, Duration.ofSeconds(10));
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void anAddedHeaderGoesBesideTheSignedIdOfTheRequest() throws Exception {
        WorkloadClient.Response response = client.postJson(EXPORT, "req-2", AT, "{\"note\":\"text\"}",
                Map.of("X-Request-ID", "req-1", "X-Contexa-Anomaly-Signal", "benign; text"));

        assertThat(response.status()).isEqualTo(200);
        Seen request = seen.get(0);
        assertThat(request.header("X-Request-ID")).isEqualTo("req-1");
        assertThat(request.header("X-Contexa-Anomaly-Signal")).isEqualTo("benign; text");
        assertThat(request.header(InternalContextHeaders.REQUEST_ID)).isEqualTo("req-2");
        assertThat(request.body()).isEqualTo("{\"note\":\"text\"}");
        InternalContext context = new InternalContext(RUN.runId(), "req-2", AT, RUN.clientIp(), RUN.device(),
                RUN.organization(), RUN.tenant());
        assertThat(signer.verify("POST", EXPORT, Long.parseLong(request.header(InternalContextHeaders.TIMESTAMP)),
                context, request.header(InternalContextHeaders.SIGNATURE)))
                .as("the signature covers the request's own id, not the added one").isTrue();
    }

    @Test
    void aGetAndAStreamCarryTheAddedHeadersToo() throws Exception {
        client.get("/api/projects", "req-1", AT, Map.of("X-Request-ID", "req-0"));
        client.openStream("/api/projects/HX-310/exports/stream?items=12", "req-2", AT, Map.of("X-Request-ID", "req-1"))
                .body().close();

        assertThat(seen).extracting(request -> request.header("X-Request-ID")).containsExactly("req-0", "req-1");
        assertThat(seen).extracting(request -> request.header(InternalContextHeaders.REQUEST_ID))
                .containsExactly("req-1", "req-2");
    }

    @Test
    void aRequestWithoutAddedHeadersSendsWhatItSentBefore() throws Exception {
        client.postJson(EXPORT, "req-1", AT, null);

        assertThat(seen.get(0).header("X-Request-ID")).isNull();
        assertThat(seen.get(0).header("X-Contexa-Anomaly-Signal")).isNull();
        assertThat(seen.get(0).body()).isEmpty();
    }

    @Test
    void noAddedHeaderReplacesTheSignedContextOrTheDevice() {
        assertThatThrownBy(() -> client.get("/api/projects", "req-1", AT,
                Map.of(InternalContextHeaders.REQUEST_ID, "req-0"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.postJson(EXPORT, "req-1", AT, null, Map.of("user-agent", "curl/8.9")))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(seen).as("nothing was sent").isEmpty();
        assertThat(WorkloadClient.isReservedHeader("x-showcase-signature")).isTrue();
        assertThat(WorkloadClient.isReservedHeader("X-Contexa-Anomaly-Signal")).isFalse();
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
