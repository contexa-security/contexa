package io.contexa.showcase.workload.contexa.observation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every model call of the engine as it really happened, kept per decision id for the portal to collect right after
 * a step (docs/showcase/데모-재설계.md 5.1, R-22, R-23): the prompt messages as sent, the provider request options
 * (everything but the messages: model, reasoning effort, output limit, response format), the provider response body,
 * and the answer text, finish reason and token counts read from that body. Retries keep their own call number.
 * <p>
 * HTTP session identifiers (32 upper-case hex digits) are the only values masked; the count of masked places is kept
 * with the call so a reader knows where the text differs from what was sent. The run principals, company data and
 * addresses in the prompts are virtual data of the demo and stay as they are.
 */
public class ModelExchanges {

    static final int MAX_DECISIONS = 1_000;
    static final int MAX_PROVIDER_BODY = 256 * 1024;
    static final Pattern SESSION_ID = Pattern.compile("\\b[0-9A-F]{32}\\b");
    static final String SESSION_MASK = "<SESSION>";

    /**
     * @param requestOptions   the provider request body without its messages, as sent; null when the call did not
     *                         reach the provider client seen by the capture
     * @param providerResponse the provider response body, masked like the prompts; null when not captured
     * @param maskedSessionIds places where an HTTP session identifier was masked in prompts, answer and body
     */
    public record Exchange(int callNo, String model, String systemPrompt, String userPrompt, String answer,
                           String finishReason, Long promptTokens, Long completionTokens, Long reasoningTokens,
                           long elapsedMs, boolean success, String failure, Instant finishedAt,
                           Map<String, Object> requestOptions, Integer httpStatus, String providerResponse,
                           int maskedSessionIds) {
    }

    /** A call in progress on the current thread; the HTTP capture fills the provider part. */
    static final class Pending {
        final String decisionId;
        final int callNo;
        final String systemPrompt;
        final String userPrompt;
        final long startedNanos;
        Map<String, Object> requestOptions;
        Integer httpStatus;
        String providerResponse;

        Pending(String decisionId, int callNo, String systemPrompt, String userPrompt) {
            this.decisionId = decisionId;
            this.callNo = callNo;
            this.systemPrompt = systemPrompt;
            this.userPrompt = userPrompt;
            this.startedNanos = System.nanoTime();
        }
    }

    private final Clock clock;
    private final ObjectMapper json;
    private final ThreadLocal<Pending> current = new ThreadLocal<>();
    private final Map<String, List<Exchange>> byDecision = new LinkedHashMap<>(256, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, List<Exchange>> eldest) {
            return size() > MAX_DECISIONS;
        }
    };

    public ModelExchanges(Clock clock, ObjectMapper json) {
        this.clock = clock;
        this.json = json;
    }

    /** Opens a call of the decision on this thread; a call without a decision id is not kept. */
    void begin(String decisionId, String systemPrompt, String userPrompt) {
        if (decisionId == null || decisionId.isBlank()) {
            current.remove();
            return;
        }
        int callNo;
        synchronized (byDecision) {
            List<Exchange> earlier = byDecision.get(decisionId);
            callNo = earlier == null ? 1 : earlier.size() + 1;
        }
        current.set(new Pending(decisionId, callNo, systemPrompt, userPrompt));
    }

    /** The call in progress on this thread, for the provider HTTP capture; null outside a decision's call. */
    Pending current() {
        return current.get();
    }

    /**
     * Closes the call on this thread. Answer, finish reason and token counts come from the provider response body
     * when it was captured; otherwise from the values the chat client reported.
     */
    void complete(String model, String clientAnswer, String clientFinishReason, Long clientPromptTokens,
                  Long clientCompletionTokens, boolean success, String failure) {
        Pending pending = current.get();
        current.remove();
        if (pending == null) {
            return;
        }
        ProviderAnswer provider = providerAnswer(pending.providerResponse);
        Masked system = mask(pending.systemPrompt);
        Masked user = mask(pending.userPrompt);
        Masked answer = mask(provider.answer() != null ? provider.answer() : clientAnswer);
        Masked body = mask(pending.providerResponse);
        Exchange exchange = new Exchange(pending.callNo,
                provider.model() != null ? provider.model() : model,
                system.text(), user.text(), answer.text(),
                provider.finishReason() != null ? provider.finishReason() : clientFinishReason,
                provider.promptTokens() != null ? provider.promptTokens() : clientPromptTokens,
                provider.completionTokens() != null ? provider.completionTokens() : clientCompletionTokens,
                provider.reasoningTokens(),
                (System.nanoTime() - pending.startedNanos) / 1_000_000L, success, failure, clock.instant(),
                pending.requestOptions, pending.httpStatus, body.text(),
                system.count() + user.count() + answer.count() + body.count());
        synchronized (byDecision) {
            byDecision.computeIfAbsent(pending.decisionId, key -> new ArrayList<>()).add(exchange);
        }
    }

    public List<Exchange> of(String decisionId) {
        synchronized (byDecision) {
            List<Exchange> exchanges = byDecision.get(decisionId);
            return exchanges == null ? List.of() : List.copyOf(exchanges);
        }
    }

    /** The provider request body without its messages: what was asked of the model besides the prompt. */
    Map<String, Object> requestOptions(byte[] body) {
        try {
            JsonNode request = json.readTree(body);
            if (request == null || !request.isObject()) {
                return Map.of("unreadable", true);
            }
            Map<String, Object> options = new LinkedHashMap<>();
            for (Map.Entry<String, JsonNode> field : request.properties()) {
                if (!"messages".equals(field.getKey())) {
                    options.put(field.getKey(), json.convertValue(field.getValue(), Object.class));
                }
            }
            options.put("messageCount", request.path("messages").size());
            return options;
        } catch (Exception e) {
            return Map.of("unreadable", true);
        }
    }

    private record ProviderAnswer(String model, String answer, String finishReason, Long promptTokens,
                                  Long completionTokens, Long reasoningTokens) {
    }

    private ProviderAnswer providerAnswer(String body) {
        if (body == null) {
            return new ProviderAnswer(null, null, null, null, null, null);
        }
        try {
            JsonNode response = json.readTree(body);
            JsonNode choice = response.path("choices").path(0);
            JsonNode usage = response.path("usage");
            return new ProviderAnswer(text(response.path("model")), text(choice.path("message").path("content")),
                    text(choice.path("finish_reason")), number(usage.path("prompt_tokens")),
                    number(usage.path("completion_tokens")),
                    number(usage.path("completion_tokens_details").path("reasoning_tokens")));
        } catch (Exception e) {
            return new ProviderAnswer(null, null, null, null, null, null);
        }
    }

    private static String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static Long number(JsonNode node) {
        return node == null || !node.isNumber() ? null : node.asLong();
    }

    record Masked(String text, int count) {
    }

    static Masked mask(String text) {
        if (text == null) {
            return new Masked(null, 0);
        }
        Matcher matcher = SESSION_ID.matcher(text);
        int count = 0;
        StringBuilder masked = new StringBuilder();
        while (matcher.find()) {
            count++;
            matcher.appendReplacement(masked, SESSION_MASK);
        }
        matcher.appendTail(masked);
        return new Masked(masked.toString(), count);
    }
}
