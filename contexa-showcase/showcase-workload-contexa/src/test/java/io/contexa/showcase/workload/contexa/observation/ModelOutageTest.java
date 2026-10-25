package io.contexa.showcase.workload.contexa.observation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** docs/agent A6-R10: the outage fails the model calls of the runs it names and no others. */
class ModelOutageTest {

    private static final String RUN = "0a1b2c3d4e5f";
    private static final String CHAT = "https://models.example/v1/chat/completions";

    private final ModelOutage outage = new ModelOutage();
    private final AtomicInteger sent = new AtomicInteger();

    private ClientHttpResponse call(HttpMethod method, String uri, String prompt) throws IOException {
        MockClientHttpRequest request = new MockClientHttpRequest(method, URI.create(uri));
        byte[] body = prompt.getBytes(StandardCharsets.UTF_8);
        return outage.intercept(request, body, (executed, bytes) -> {
            sent.incrementAndGet();
            return new MockClientHttpResponse(new byte[0], HttpStatus.OK);
        });
    }

    @Test
    void withoutAnOutageEveryCallPassesOn() throws IOException {
        assertThat(call(HttpMethod.POST, CHAT, "Subject: agt-" + RUN + "-report").getStatusCode())
                .isEqualTo(HttpStatus.OK);
        assertThat(sent).hasValue(1);
        assertThat(outage.refusedCalls()).isZero();
    }

    @Test
    void aMarkedRunsModelCallFailsWithTheQuotaErrorBeforeItLeavesAndOthersPassOn() throws IOException {
        outage.begin(RUN);

        ClientHttpResponse failed = call(HttpMethod.POST, CHAT, "Subject: agt-" + RUN + "-report, through " + RUN);
        assertThat(failed.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(new String(failed.getBody().readAllBytes(), StandardCharsets.UTF_8)).contains("insufficient_quota");
        assertThat(sent).as("the call never left the host").hasValue(0);
        assertThat(outage.refusedCalls()).isEqualTo(1);

        assertThat(call(HttpMethod.POST, CHAT, "Subject: agt-ffffffffffff-report").getStatusCode())
                .as("another run's call").isEqualTo(HttpStatus.OK);
        assertThat(call(HttpMethod.POST, "https://models.example/v1/messages", "agt-" + RUN).getStatusCode())
                .as("the other provider's path fails too").isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(call(HttpMethod.GET, CHAT, RUN).getStatusCode()).as("a read is no model call")
                .isEqualTo(HttpStatus.OK);
        assertThat(call(HttpMethod.POST, "https://models.example/v1/embeddings", RUN).getStatusCode())
                .as("an embedding call is no judging call").isEqualTo(HttpStatus.OK);

        outage.end(RUN);
        assertThat(call(HttpMethod.POST, CHAT, "agt-" + RUN).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(outage.runs()).isEmpty();
    }

    @Test
    void aRunMarkerIsTwelveHexadecimalDigits() {
        assertThatThrownBy(() -> outage.begin("not-a-run")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> outage.begin(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> outage.begin("0A1B2C3D4E5F")).isInstanceOf(IllegalArgumentException.class);
        assertThat(outage.runs()).isEmpty();
    }
}
