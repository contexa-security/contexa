package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * sandbox prompt trace store.
 *
 * Important:
 * - Prompt data is captured when PromptGenerationStep runs.
 * - The snapshot is exposed to tests only after Layer1 analyzeWithContext fully finishes.
 * - This means the test sees a trace only after prompt generation, decision post-processing,
 *   and vector memory storage have all completed for that round.
 */
@Component
public class SandboxPromptTraceStore {

    private static final Logger log = LoggerFactory.getLogger(SandboxPromptTraceStore.class);
    private final SandboxRetrievalAuditStore sandboxRetrievalAuditStore;

    private final ConcurrentMap<String, SandboxPromptTraceSnapshot> pendingSnapshotsByEventId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SandboxPromptTraceSnapshot> completedSnapshotsByRequestId = new ConcurrentHashMap<>();
    private final AtomicReference<SandboxPromptTraceSnapshot> latestCompletedSnapshot = new AtomicReference<>();
    private final AtomicReference<SandboxPromptTraceSnapshot> latestPendingSnapshot = new AtomicReference<>();
    private final Deque<SandboxPromptTraceSnapshot> recentCompletedSnapshots = new ArrayDeque<>();

    public SandboxPromptTraceStore(SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        this.sandboxRetrievalAuditStore = sandboxRetrievalAuditStore;
    }

    public void capture(SecurityDecisionContext context, PromptGenerationResult promptGenerationResult) {
        Assert.notNull(context, "context must not be null");
        Assert.notNull(promptGenerationResult, "promptGenerationResult must not be null");

        SecurityEvent securityEvent = context.getSecurityEvent();
        if (securityEvent == null || !StringUtils.hasText(securityEvent.getEventId())) {
            return;
        }

        String requestId = extractRequestId(securityEvent, null);
        SandboxPromptTraceSnapshot snapshot = new SandboxPromptTraceSnapshot(
                requestId,
                Instant.now(),
                securityEvent,
                context.getSessionContext(),
                context.getBehaviorAnalysis(),
                context.getRelatedDocuments(),
                sandboxRetrievalAuditStore.snapshot(securityEvent),
                promptGenerationResult.getRawSystemPrompt(),
                promptGenerationResult.getRawUserPrompt(),
                promptGenerationResult.getSystemPrompt(),
                promptGenerationResult.getUserPrompt(),
                promptGenerationResult.getMetadata(),
                promptGenerationResult.getPromptExecutionMetadata()
        );

        pendingSnapshotsByEventId.put(securityEvent.getEventId(), snapshot);
        latestPendingSnapshot.set(snapshot);
        log.info("[SandboxPromptTrace] Captured pending prompt trace requestId={}, eventId={}, relatedDocuments={}",
                requestId,
                securityEvent.getEventId(),
                context.getRelatedDocuments() != null ? context.getRelatedDocuments().size() : 0);
    }

    public void complete(SecurityEvent event) {
        Assert.notNull(event, "event must not be null");
        if (!StringUtils.hasText(event.getEventId())) {
            return;
        }

        SandboxPromptTraceSnapshot pendingSnapshot = pendingSnapshotsByEventId.remove(event.getEventId());
        if (pendingSnapshot == null) {
            return;
        }
        latestPendingSnapshot.compareAndSet(pendingSnapshot, null);

        String completedRequestId = extractRequestId(event, pendingSnapshot.requestId());
        SandboxPromptTraceSnapshot completedSnapshot = new SandboxPromptTraceSnapshot(
                completedRequestId,
                pendingSnapshot.capturedAt(),
                pendingSnapshot.event(),
                pendingSnapshot.sessionContext(),
                pendingSnapshot.behaviorAnalysis(),
                pendingSnapshot.relatedDocuments(),
                sandboxRetrievalAuditStore.snapshot(event),
                pendingSnapshot.rawSystemPrompt(),
                pendingSnapshot.rawUserPrompt(),
                pendingSnapshot.systemPrompt(),
                pendingSnapshot.userPrompt(),
                pendingSnapshot.metadata(),
                pendingSnapshot.promptExecutionMetadata()
        );

        if (StringUtils.hasText(completedRequestId)) {
            completedSnapshotsByRequestId.put(completedRequestId, completedSnapshot);
        }
        latestCompletedSnapshot.set(completedSnapshot);
        synchronized (recentCompletedSnapshots) {
            recentCompletedSnapshots.addLast(completedSnapshot);
            while (recentCompletedSnapshots.size() > 32) {
                recentCompletedSnapshots.removeFirst();
            }
        }

        log.info("[SandboxPromptTrace] Completed prompt trace requestId={}, eventId={}",
                completedRequestId,
                event.getEventId());
    }

    public Optional<SandboxPromptTraceSnapshot> find(String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(completedSnapshotsByRequestId.get(requestId));
    }

    public Optional<SandboxPromptTraceSnapshot> findPending(String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return Optional.empty();
        }
        return pendingSnapshotsByEventId.values().stream()
                .filter(snapshot -> requestId.equals(snapshot.requestId()))
                .findFirst();
    }

    public SandboxPromptTraceSnapshot await(String requestId, Duration timeout) {
        Assert.hasText(requestId, "requestId must not be blank");
        Assert.notNull(timeout, "timeout must not be null");

        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() <= deadline) {
            SandboxPromptTraceSnapshot snapshot = completedSnapshotsByRequestId.get(requestId);
            if (snapshot != null) {
                return snapshot;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new IllegalStateException("Timed out waiting for completed sandbox prompt trace. requestId=" + requestId);
    }

    public SandboxPromptTraceSnapshot awaitAny(Duration timeout) {
        Assert.notNull(timeout, "timeout must not be null");

        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() <= deadline) {
            SandboxPromptTraceSnapshot snapshot = latestCompletedSnapshot.get();
            if (snapshot != null) {
                return snapshot;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new IllegalStateException("Timed out waiting for any completed sandbox prompt trace.");
    }

    public Optional<SandboxPromptTraceSnapshot> findLatest() {
        return Optional.ofNullable(latestCompletedSnapshot.get());
    }

    public Optional<SandboxPromptTraceSnapshot> findLatestPending() {
        return Optional.ofNullable(latestPendingSnapshot.get());
    }

    public void clear(String requestId) {
        if (StringUtils.hasText(requestId)) {
            completedSnapshotsByRequestId.remove(requestId);
        }
    }

    public void clearAll() {
        pendingSnapshotsByEventId.clear();
        completedSnapshotsByRequestId.clear();
        latestCompletedSnapshot.set(null);
        latestPendingSnapshot.set(null);
        sandboxRetrievalAuditStore.clearAll();
        synchronized (recentCompletedSnapshots) {
            recentCompletedSnapshots.clear();
        }
    }

    private String extractRequestId(SecurityEvent securityEvent, String fallbackRequestId) {
        if (securityEvent == null || securityEvent.getMetadata() == null) {
            return fallbackRequestId;
        }

        Object requestId = securityEvent.getMetadata().get("requestId");
        if (requestId instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        Object correlationId = securityEvent.getMetadata().get("correlationId");
        if (correlationId instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        return fallbackRequestId;
    }
}
