package io.contexa.showcase.workload.contexa.model;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Control D's start check of the Layer 2 model (DD-38): Layer 2 runs on Claude Sonnet 5.5, and the start stops with the
 * reason when its key is missing or refused, instead of every escalated decision falling back to the additional check.
 * The Anthropic API is a local server here; no model is called.
 */
class Layer2AnthropicConfigurationTest {

    private static final String MODEL = "claude-sonnet-5-5";

    private HttpServer server;
    private final AtomicReference<String> key = new AtomicReference<>();
    private final AtomicReference<String> path = new AtomicReference<>();

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String serve(int status) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            key.set(exchange.getRequestHeaders().getFirst("x-api-key"));
            path.set(exchange.getRequestURI().getPath());
            byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void anAcceptedKeyWithTheModelPassesAndNothingButTheModelListingIsAsked() throws Exception {
        String base = serve(200);

        AnthropicAvailability.Result result = AnthropicAvailability.check(base, "a-real-looking-key", MODEL);

        assertThat(result.outcome()).isEqualTo(AnthropicAvailability.Outcome.ACCEPTED);
        assertThat(key.get()).isEqualTo("a-real-looking-key");
        assertThat(path.get()).isEqualTo("/v1/models/" + MODEL);
        assertThatCode(() -> Layer2AnthropicConfiguration.verify(MODEL, MODEL, "a-real-looking-key", base))
                .doesNotThrowAnyException();
    }

    @Test
    void aRefusedKeyStopsTheStartWithTheReason() throws Exception {
        String base = serve(401);

        assertThat(AnthropicAvailability.check(base, "bad", MODEL).outcome())
                .isEqualTo(AnthropicAvailability.Outcome.REFUSED_KEY);
        assertThatThrownBy(() -> Layer2AnthropicConfiguration.verify(MODEL, MODEL, "bad", base))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("refused the key (HTTP 401)")
                .hasMessageContaining("ANTHROPIC_API_KEY");
    }

    @Test
    void aKeyWithoutTheModelStopsTheStartWithTheReason() throws Exception {
        String base = serve(404);

        assertThatThrownBy(() -> Layer2AnthropicConfiguration.verify(MODEL, MODEL, "a-key", base))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no model of that name");
    }

    @Test
    void aMissingKeyStopsTheStartWithoutAskingTheApi() {
        assertThatThrownBy(() -> Layer2AnthropicConfiguration.verify(MODEL, MODEL, " ", "http://127.0.0.1:1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no Anthropic key is set");
    }

    @Test
    void anApiThatCannotBeReadDoesNotStopTheStart() throws Exception {
        String base = serve(500);

        assertThat(AnthropicAvailability.check(base, "a-key", MODEL).outcome())
                .isEqualTo(AnthropicAvailability.Outcome.UNKNOWN);
        assertThatCode(() -> Layer2AnthropicConfiguration.verify(MODEL, MODEL, "a-key", base))
                .doesNotThrowAnyException();
        assertThatCode(() -> Layer2AnthropicConfiguration.verify(MODEL, MODEL, "a-key", "http://127.0.0.1:1"))
                .doesNotThrowAnyException();
    }

    @Test
    void aLayerTwoOnAnotherModelIsNotChecked() {
        assertThatCode(() -> Layer2AnthropicConfiguration.verify("gpt-6.1-sol", MODEL, "", "http://127.0.0.1:1"))
                .doesNotThrowAnyException();
        assertThatCode(() -> Layer2AnthropicConfiguration.verify("", MODEL, "", "http://127.0.0.1:1"))
                .doesNotThrowAnyException();
    }
}
