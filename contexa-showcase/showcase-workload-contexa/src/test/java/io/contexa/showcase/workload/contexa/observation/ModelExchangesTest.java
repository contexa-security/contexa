package io.contexa.showcase.workload.contexa.observation;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Each model call of a decision is kept as it happened: the prompt messages as sent, the provider request options
 * without the messages, the provider response body, and the answer, finish reason and token counts read from that
 * body; retries get their own number; only HTTP session identifiers are masked and counted
 * (docs/showcase/데모-재설계.md 5.1, R-22, R-23, R-30).
 */
class ModelExchangesTest {

    private static final String SESSION = "0123456789ABCDEF0123456789ABCDEF";
    private static final String REQUEST = """
            {"model":"gpt-5-nano","reasoning_effort":"minimal","max_completion_tokens":256,
             "messages":[{"role":"system","content":"rules"},{"role":"user","content":"facts"}]}""";
    private static final String RESPONSE = """
            {"model":"gpt-5-nano-2025-08-07","choices":[{"finish_reason":"stop",
             "message":{"content":"{\\"action\\":\\"ALLOW\\",\\"reasoning\\":\\"Session %s looks normal.\\"}"}}],
             "usage":{"prompt_tokens":7624,"completion_tokens":93,
                      "completion_tokens_details":{"reasoning_tokens":0}}}""".formatted(SESSION);

    private static final String ANTHROPIC_REQUEST = """
            {"model":"claude-haiku-5-5","max_tokens":2048,
             "system":[{"type":"text","text":"rules","cache_control":{"type":"ephemeral"}}],
             "messages":[{"role":"user","content":"facts"}]}""";
    private static final String ANTHROPIC_RESPONSE = """
            {"model":"claude-haiku-5-5","type":"message","stop_reason":"end_turn",
             "content":[{"type":"thinking","thinking":"The user works here.","signature":"sig"},
                        {"type":"text","text":"{\\"action\\":\\"ALLOW\\"}"}],
             "usage":{"input_tokens":3329,"cache_creation_input_tokens":0,"cache_read_input_tokens":4372,
                      "output_tokens":838,"output_tokens_details":{"thinking_tokens":734}}}""";

    private final ModelExchanges exchanges = new ModelExchanges(
            Clock.fixed(Instant.parse("2026-10-06T00:00:00Z"), ZoneOffset.UTC), new ObjectMapper());
    private final ProviderHttpCapture capture = new ProviderHttpCapture(exchanges);

    @Test
    void keepsEachCallOfADecisionWithWhatWasSentAndWhatCameBack() throws Exception {
        exchanges.begin("req-1", "rules", "facts for session " + SESSION);
        ClientHttpResponse response = capture.intercept(request(HttpMethod.POST, "/v1/chat/completions"),
                REQUEST.getBytes(StandardCharsets.UTF_8), (request, body) -> reply(RESPONSE));
        assertThat(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8))
                .as("the chat client reads the provider body unchanged").isEqualTo(RESPONSE);
        exchanges.complete("client-model", "client answer", "CLIENT", 1L, 2L, true, null);

        exchanges.begin("req-1", "rules", "facts, retry");
        exchanges.complete("gpt-5-nano", "second answer", "STOP", 10L, 20L, true, null);

        List<ModelExchanges.Exchange> calls = exchanges.of("req-1");
        assertThat(calls).extracting(ModelExchanges.Exchange::callNo).containsExactly(1, 2);
        ModelExchanges.Exchange first = calls.get(0);
        assertThat(first.model()).isEqualTo("gpt-5-nano-2025-08-07");
        assertThat(first.finishReason()).isEqualTo("stop");
        assertThat(first.promptTokens()).isEqualTo(7624L);
        assertThat(first.completionTokens()).isEqualTo(93L);
        assertThat(first.reasoningTokens()).isZero();
        assertThat(first.answer()).contains("\"action\":\"ALLOW\"").contains("<SESSION>").doesNotContain(SESSION);
        assertThat(first.userPrompt()).isEqualTo("facts for session <SESSION>");
        assertThat(first.providerResponse()).doesNotContain(SESSION);
        assertThat(first.maskedSessionIds()).isEqualTo(3);
        assertThat(first.httpStatus()).isEqualTo(200);
        assertThat(first.requestOptions()).containsEntry("reasoning_effort", "minimal")
                .containsEntry("max_completion_tokens", 256).containsEntry("messageCount", 2)
                .doesNotContainKey("messages");

        ModelExchanges.Exchange retry = calls.get(1);
        assertThat(retry.requestOptions()).as("no provider exchange was seen for this call").isNull();
        assertThat(retry.answer()).isEqualTo("second answer");
        assertThat(retry.finishReason()).isEqualTo("STOP");
        assertThat(retry.reasoningTokens()).isNull();
    }

    /**
     * An Anthropic Messages call (model comparison): the answer is the text after the thinking, the prompt tokens are
     * every input token as OpenAI counts them (the uncached ones, the cache reads and the cache writes), the thinking
     * tokens are the reasoning tokens, and the system prompt is kept as the system prompt, not as an option.
     */
    @Test
    void keepsAnAnthropicCallWithItsAnswerAfterTheThinkingAndEveryInputToken() throws Exception {
        exchanges.begin("req-4", "rules", "facts");
        capture.intercept(request(HttpMethod.POST, "/v1/messages"), ANTHROPIC_REQUEST.getBytes(StandardCharsets.UTF_8),
                (request, body) -> reply(ANTHROPIC_RESPONSE));
        exchanges.complete("client-model", "client answer", "CLIENT", 1L, 2L, true, null);

        ModelExchanges.Exchange call = exchanges.of("req-4").get(0);
        assertThat(call.model()).isEqualTo("claude-haiku-5-5");
        assertThat(call.answer()).isEqualTo("{\"action\":\"ALLOW\"}");
        assertThat(call.finishReason()).isEqualTo("end_turn");
        assertThat(call.promptTokens()).isEqualTo(7701L);
        assertThat(call.completionTokens()).isEqualTo(838L);
        assertThat(call.reasoningTokens()).isEqualTo(734L);
        assertThat(call.requestOptions()).containsEntry("max_tokens", 2048).containsEntry("messageCount", 1)
                .containsEntry("systemCacheBlocks", 1).doesNotContainKey("system").doesNotContainKey("messages");
        assertThat(call.providerResponse()).contains("\"cache_read_input_tokens\":4372");
    }

    @Test
    void leavesEveryOtherHttpCallAndCallsWithoutADecisionAlone() throws Exception {
        AtomicInteger executed = new AtomicInteger();
        exchanges.begin("req-2", "rules", "facts");
        capture.intercept(request(HttpMethod.POST, "/v1/embeddings"), new byte[0], (request, body) -> {
            executed.incrementAndGet();
            return reply("{}");
        });
        exchanges.complete("m", "a", "STOP", 1L, 1L, true, null);
        assertThat(exchanges.of("req-2").get(0).requestOptions()).isNull();

        exchanges.begin(null, "rules", "facts");
        capture.intercept(request(HttpMethod.POST, "/v1/chat/completions"), REQUEST.getBytes(StandardCharsets.UTF_8),
                (request, body) -> {
                    executed.incrementAndGet();
                    return reply(RESPONSE);
                });
        exchanges.complete("m", "a", "STOP", 1L, 1L, true, null);
        assertThat(executed).hasValue(2);
        assertThat(exchanges.of("null")).isEmpty();
    }

    @Test
    void recordsAFailedCallWithItsFailure() {
        exchanges.begin("req-3", "rules", "facts");
        exchanges.complete(null, null, null, null, null, false, "ResourceAccessException");

        ModelExchanges.Exchange failed = exchanges.of("req-3").get(0);
        assertThat(failed.success()).isFalse();
        assertThat(failed.failure()).isEqualTo("ResourceAccessException");
        assertThat(failed.answer()).isNull();
    }

    private static HttpRequest request(HttpMethod method, String path) {
        return new HttpRequest() {
            @Override
            public HttpMethod getMethod() {
                return method;
            }

            @Override
            public URI getURI() {
                return URI.create("https://api.openai.com" + path);
            }

            @Override
            public Map<String, Object> getAttributes() {
                return new HashMap<>();
            }

            @Override
            public HttpHeaders getHeaders() {
                return new HttpHeaders();
            }
        };
    }

    private static ClientHttpResponse reply(String body) {
        return new ClientHttpResponse() {
            @Override
            public HttpStatusCode getStatusCode() {
                return HttpStatus.OK;
            }

            @Override
            public String getStatusText() {
                return "OK";
            }

            @Override
            public HttpHeaders getHeaders() {
                return new HttpHeaders();
            }

            @Override
            public InputStream getBody() {
                return new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public void close() {
            }
        };
    }
}
