package io.contexa.showcase.workload.contexa.observation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Model usage measured in control D, kept per decision id (the orchestrator's request id) for the portal to collect
 * right after a run. Bounded: the oldest decisions are dropped first. Calls that carry no decision id (embeddings of
 * stored memory documents, for example) are counted as unattributed.
 */
public class UsageLedger {

    static final int MAX_DECISIONS = 20_000;

    /**
     * @param kind             CHAT or EMBEDDING
     * @param promptSha256     hash of the normalised prompt (PromptFingerprint), for the isolation checks
     * @param promptPrincipals run principals the prompt mentions
     * @param systemPromptSha256 hash of the system message as sent; the execution specification's prompt hash
     */
    public record ModelCall(String kind, String model, long promptTokens, long completionTokens, long totalTokens,
                            long elapsedMs, boolean success, Instant finishedAt, String promptSha256,
                            Set<String> promptPrincipals, String systemPromptSha256) {
    }

    public record Unattributed(long chatCalls, long chatTokens, long embeddingCalls, long embeddingTokens) {
    }

    private final Map<String, List<ModelCall>> calls = new LinkedHashMap<>(256, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, List<ModelCall>> eldest) {
            return size() > MAX_DECISIONS;
        }
    };

    private final AtomicLong unattributedChatCalls = new AtomicLong();
    private final AtomicLong unattributedChatTokens = new AtomicLong();
    private final AtomicLong unattributedEmbeddingCalls = new AtomicLong();
    private final AtomicLong unattributedEmbeddingTokens = new AtomicLong();

    public void record(String key, ModelCall call) {
        if (key == null || key.isBlank()) {
            if ("EMBEDDING".equals(call.kind())) {
                unattributedEmbeddingCalls.incrementAndGet();
                unattributedEmbeddingTokens.addAndGet(call.totalTokens());
            } else {
                unattributedChatCalls.incrementAndGet();
                unattributedChatTokens.addAndGet(call.totalTokens());
            }
            return;
        }
        synchronized (calls) {
            calls.computeIfAbsent(key, ignored -> new ArrayList<>()).add(call);
        }
    }

    public List<ModelCall> callsOf(String key) {
        synchronized (calls) {
            List<ModelCall> found = calls.get(key);
            return found == null ? List.of() : List.copyOf(found);
        }
    }

    /** Normalised prompts of recent decisions, kept to explain an isolation check that fails. */
    private final Map<String, String> normalisedPrompts = new LinkedHashMap<>(64, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > MAX_PROMPTS;
        }
    };

    static final int MAX_PROMPTS = 500;

    public void keepPrompt(String key, String normalisedPrompt) {
        if (key == null) {
            return;
        }
        synchronized (normalisedPrompts) {
            normalisedPrompts.put(key, normalisedPrompt);
        }
    }

    public String promptOf(String key) {
        synchronized (normalisedPrompts) {
            return normalisedPrompts.get(key);
        }
    }

    public Unattributed unattributed() {
        return new Unattributed(unattributedChatCalls.get(), unattributedChatTokens.get(),
                unattributedEmbeddingCalls.get(), unattributedEmbeddingTokens.get());
    }
}
