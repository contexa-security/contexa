package io.contexa.showcase.workload.contexa.observation;

import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.MessageType;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.Usage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.HexFormat;

/**
 * Measures every chat call of the engine (tokens and time) and attributes it to the decision id the engine passes
 * in the advisor context (docs/showcase/ADR.md ADR-25). It only measures: it never refuses or changes a call, so
 * a budget decision can never turn an analysis into a technical fallback (plan section 2). Ordered after the
 * engine's structured output validation, so every retry is counted.
 */
public class LlmUsageMeter extends BaseAdvisor {

    private static final char LINE_END = 0x0a;

    private final UsageLedger ledger;
    private final Clock clock;

    public LlmUsageMeter(UsageLedger ledger, Clock clock) {
        super("showcase", "llm-usage-meter", Integer.MAX_VALUE - 100);
        this.ledger = ledger;
        this.clock = clock;
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        long started = System.nanoTime();
        ChatClientResponse response = null;
        try {
            response = chain.nextCall(request);
            return response;
        } finally {
            record(request, response, (System.nanoTime() - started) / 1_000_000L);
        }
    }

    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {
        return request;
    }

    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        return response;
    }

    private void record(ChatClientRequest request, ChatClientResponse response, long elapsedMs) {
        String decisionId = null;
        Object observation = request.context().get(LlmObservationContext.CONTEXT_KEY);
        if (observation instanceof LlmObservationContext context) {
            decisionId = context.requestId();
        }
        String model = null;
        long prompt = 0;
        long completion = 0;
        long total = 0;
        boolean success = response != null && response.chatResponse() != null;
        if (success) {
            ChatResponseMetadata metadata = response.chatResponse().getMetadata();
            model = metadata.getModel();
            Usage usage = metadata.getUsage();
            if (usage != null) {
                prompt = value(usage.getPromptTokens());
                completion = value(usage.getCompletionTokens());
                total = value(usage.getTotalTokens());
            }
        }
        String promptText = promptText(request);
        PromptFingerprint.Fingerprint fingerprint = PromptFingerprint.of(promptText);
        ledger.record(decisionId, new UsageLedger.ModelCall("CHAT", model, prompt, completion, total, elapsedMs,
                success, clock.instant(), fingerprint.normalisedSha256(), fingerprint.principals(),
                systemPromptSha256(request)));
        ledger.keepPrompt(decisionId, PromptFingerprint.normalise(promptText));
    }

    private static String promptText(ChatClientRequest request) {
        if (request.prompt() == null) {
            return "";
        }
        StringBuilder text = new StringBuilder();
        for (Message message : request.prompt().getInstructions()) {
            text.append('[').append(message.getMessageType()).append(']').append(LINE_END);
            text.append(message.getText() == null ? "" : message.getText()).append(LINE_END);
        }
        return text.toString();
    }

    /** SHA-256 of the system messages exactly as sent (the security decision rules, identical for every user). */
    static String systemPromptSha256(ChatClientRequest request) {
        if (request.prompt() == null) {
            return null;
        }
        StringBuilder system = new StringBuilder();
        for (Message message : request.prompt().getInstructions()) {
            if (message.getMessageType() == MessageType.SYSTEM && message.getText() != null) {
                system.append(message.getText()).append(LINE_END);
            }
        }
        if (system.length() == 0) {
            return null;
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(system.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static long value(Integer tokens) {
        return tokens == null ? 0 : tokens;
    }
}
