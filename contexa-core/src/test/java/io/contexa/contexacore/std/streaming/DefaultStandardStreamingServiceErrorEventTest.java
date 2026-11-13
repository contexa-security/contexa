package io.contexa.contexacore.std.streaming;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Flux;

import java.net.ConnectException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IAM-D62: a failed stream ends with one event named "error" whose data is {"code", "message"}, the cause read through
 * any wrapping, and never with an "ERROR:" text chunk that reads like part of the answer.
 */
class DefaultStandardStreamingServiceErrorEventTest {

    private final ObjectMapper json = new ObjectMapper();
    private final DefaultStandardStreamingService service =
            new DefaultStandardStreamingService(new StreamingProperties(), json);

    @Test
    @SuppressWarnings("unchecked")
    void aStreamWhoseModelServerCannotBeReachedEndsWithItsErrorEvent() throws Exception {
        AICoreOperations<DomainContext> operations = mock(AICoreOperations.class);
        WebClientRequestException refused = new WebClientRequestException(new ConnectException("Connection refused"),
                HttpMethod.POST, URI.create("http://127.0.0.1:11435/api/chat"), new HttpHeaders());
        when(operations.processStream(any(AIRequest.class))).thenReturn(
                Flux.error(new AIOperationException("Streaming strategic operation failed", refused)));

        AIRequest<DomainContext> request = mock(AIRequest.class);

        List<ServerSentEvent<String>> events = service.stream(request, operations)
                .collectList().block(Duration.ofSeconds(10));

        assertThat(events).singleElement().satisfies(event -> {
            assertThat(event.event()).isEqualTo(DefaultStandardStreamingService.ERROR_EVENT);
            assertThat(event.data()).doesNotStartWith("ERROR");
        });
        Map<String, Object> failure = json.readValue(events.get(0).data(), Map.class);
        assertThat(failure).containsEntry("code", DefaultStandardStreamingService.MODEL_UNREACHABLE)
                .containsKey("message");
    }

    @Test
    void anErrorStreamIsOneNamedEvent() throws Exception {
        List<ServerSentEvent<String>> events = service.errorStream("VALIDATION_ERROR", "naturalLanguageQuery is required")
                .collectList().block(Duration.ofSeconds(5));

        assertThat(events).singleElement().extracting(ServerSentEvent::event).isEqualTo("error");
        assertThat(json.readTree(events.get(0).data()).get("code").asText()).isEqualTo("VALIDATION_ERROR");
    }
}
