package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * The prompt of a security decision, kept from its generation until its sealed evidence package is assembled.
 *
 * Lifecycle:
 * 1. capture() -- called by SealedEvidencePromptCaptureAspect when PromptGenerator.generatePrompt() completes
 * 2. complete() -- called by SealedEvidenceLayer1CompletionAspect when Layer1.evaluate() finishes
 * 3. consume() -- called once by the capture handler when it seals the decision
 *
 * Only a completed snapshot is handed out, and only under the trace key it was completed with. The snapshot keeps the
 * prompt metadata as the prompt generation gave it.
 */
public class SealedEvidencePromptTraceStore {

    private final ConcurrentMap<String, SealedEvidencePromptSnapshot> pendingByTraceKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SealedEvidencePromptSnapshot> completedByTraceKey = new ConcurrentHashMap<>();

    private final VerificationCaptureStoreOptions options;
    private final Clock clock;

    public SealedEvidencePromptTraceStore() {
        this(VerificationCaptureStoreOptions.defaults(), Clock.systemUTC());
    }

    public SealedEvidencePromptTraceStore(VerificationCaptureStoreOptions options, Clock clock) {
        this.options = Objects.requireNonNull(options, "options must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    /**
     * Called by SealedEvidencePromptCaptureAspect at PromptGenerator.generatePrompt() completion.
     * Stores the prompt snapshot as pending (not yet completed by Layer1).
     */
    public void capture(SecurityDecisionContext context, PromptGenerationResult promptResult) {
        if (context == null || promptResult == null) {
            return;
        }
        SecurityEvent event = context.getSecurityEvent();
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            return;
        }
        pruneSnapshots();
        List<Document> relatedDocuments = context.getRelatedDocuments();
        Map<String, Object> metadata = promptResult.getMetadata();
        pendingByTraceKey.put(resolveTraceKey(event), new SealedEvidencePromptSnapshot(
                resolveRequestId(event),
                clock.instant(),
                event,
                context.getSessionContext(),
                context.getBehaviorAnalysis(),
                relatedDocuments != null ? List.copyOf(relatedDocuments) : List.of(),
                promptResult.getRawSystemPrompt(),
                promptResult.getRawUserPrompt(),
                promptResult.getSystemPrompt(),
                promptResult.getUserPrompt(),
                metadata != null ? Collections.unmodifiableMap(new LinkedHashMap<>(metadata)) : Map.of(),
                promptResult.getPromptExecutionMetadata()));
        pruneSnapshots();
    }

    /**
     * Called by SealedEvidenceLayer1CompletionAspect when Layer1.evaluate() finishes.
     * Moves the snapshot from pending to completed under the same trace key.
     */
    public void complete(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            return;
        }
        pruneSnapshots();
        String traceKey = resolveTraceKey(event);
        SealedEvidencePromptSnapshot pending = pendingByTraceKey.remove(traceKey);
        if (pending == null) {
            return;
        }
        completedByTraceKey.put(traceKey, new SealedEvidencePromptSnapshot(
                resolveRequestId(event),
                pending.capturedAt(),
                event,
                pending.sessionContext(),
                pending.behaviorAnalysis(),
                pending.relatedDocuments(),
                pending.rawSystemPrompt(),
                pending.rawUserPrompt(),
                pending.systemPrompt(),
                pending.userPrompt(),
                pending.metadata(),
                pending.promptExecutionMetadata()));
        pruneSnapshots();
    }

    /**
     * Called by the capture handler to retrieve and remove the completed snapshot of a trace key.
     * Single-use: once consumed, the snapshot is removed from the store.
     */
    public SealedEvidencePromptSnapshot consume(String traceKey) {
        if (!StringUtils.hasText(traceKey)) {
            return null;
        }
        pruneSnapshots();
        return completedByTraceKey.remove(traceKey);
    }

    /**
     * Non-destructive lookup of a completed snapshot by its trace key or request ID.
     */
    public SealedEvidencePromptSnapshot find(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return null;
        }
        pruneSnapshots();
        SealedEvidencePromptSnapshot direct = completedByTraceKey.get(requestId);
        if (direct != null) {
            return direct;
        }
        return completedByTraceKey.values().stream()
                .filter(snapshot -> requestId.equals(snapshot.requestId()))
                .findFirst()
                .orElse(null);
    }

    private String resolveTraceKey(SecurityEvent event) {
        if (event != null && event.getMetadata() != null) {
            Object identity = event.getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
            if (identity != null && StringUtils.hasText(identity.toString())) {
                return identity.toString().trim();
            }
        }
        return resolveRequestId(event);
    }

    private String resolveRequestId(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object rid = event.getMetadata().get("requestId");
            if (rid != null && !rid.toString().isBlank()) {
                return rid.toString();
            }
            Object cid = event.getMetadata().get("correlationId");
            if (cid != null && !cid.toString().isBlank()) {
                return cid.toString();
            }
        }
        return event.getEventId();
    }

    private void pruneSnapshots() {
        Instant cutoff = clock.instant().minus(options.snapshotTtl());
        pruneMap(pendingByTraceKey, cutoff, options.maxPending());
        pruneMap(completedByTraceKey, cutoff, options.maxCompleted());
    }

    private void pruneMap(
            ConcurrentMap<String, SealedEvidencePromptSnapshot> snapshots,
            Instant cutoff,
            int maximumSize
    ) {
        snapshots.entrySet().removeIf(entry -> entry.getValue().capturedAt().isBefore(cutoff));
        while (snapshots.size() > maximumSize) {
            snapshots.entrySet().stream()
                    .min(Comparator.comparing(entry -> entry.getValue().capturedAt()))
                    .ifPresent(entry -> snapshots.remove(entry.getKey(), entry.getValue()));
        }
    }
}
