package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SealedEvidencePromptTraceStoreTest {

    private SealedEvidencePromptTraceStore store;

    @BeforeEach
    void setUp() {
        store = new SealedEvidencePromptTraceStore();
    }

    @Test
    void captureAndConsumeLifecycle() {
        SecurityEvent event = buildEvent("req-001", "evt-001");
        PromptGenerationResult promptResult = mockPromptResult();
        VerificationCaptureContext context = mockContext(event, promptResult);

        store.capture(context);
        store.complete(event);

        SealedEvidencePromptSnapshot snapshot = store.consume("req-001");
        assertThat(snapshot).isNotNull();
        assertThat(snapshot.requestId()).isEqualTo("req-001");
        assertThat(snapshot.systemPrompt()).isEqualTo("system prompt");
        assertThat(snapshot.userPrompt()).isEqualTo("user prompt");
        assertThat(snapshot.metadata()).containsKeys(
                "promptSourceContextLedger",
                "promptRawUserFieldLedger",
                "promptFinalUserFieldLedger",
                "promptUserFieldDiffLedger",
                "promptFieldStateLedger",
                "promptFieldStateSummary");
        assertThat(snapshot.metadata().get("promptFieldStateLedger")).asList().isNotEmpty();
    }

    @Test
    void consumeReturnNullForUnknownRequestId() {
        assertThat(store.consume("nonexistent")).isNull();
    }

    @Test
    void consumeRemovesSnapshotFromStore() {
        SecurityEvent event = buildEvent("req-002", "evt-002");
        store.capture(mockContext(event, mockPromptResult()));
        store.complete(event);

        SealedEvidencePromptSnapshot first = store.consume("req-002");
        SealedEvidencePromptSnapshot second = store.consume("req-002");

        assertThat(first).isNotNull();
        assertThat(second).isNull();
    }

    @Test
    void pendingSnapshotCanBeConsumedWhenLayer1CompletionWasNotObserved() {
        SecurityEvent event = buildEvent("req-003", "evt-003");
        store.capture(mockContext(event, mockPromptResult()));
        // Not calling complete()

        SealedEvidencePromptSnapshot snapshot = store.consume("req-003");

        assertThat(snapshot).isNotNull();
        assertThat(snapshot.requestId()).isEqualTo("req-003");
        assertThat(store.consume("req-003")).isNull();
    }

    @Test
    void findDoesNotRemoveSnapshot() {
        SecurityEvent event = buildEvent("req-004", "evt-004");
        store.capture(mockContext(event, mockPromptResult()));
        store.complete(event);

        assertThat(store.find("req-004")).isNotNull();
        assertThat(store.find("req-004")).isNotNull();
    }

    @Test
    void captureIgnoresNullContext() {
        store.capture(null);
        // No exception
    }

    @Test
    void captureIgnoresNullPromptResult() {
        SecurityEvent event = buildEvent("req-005", "evt-005");
        store.capture(mockContext(event, null));
        // No exception
    }

    @Test
    void completeIgnoresEventWithoutPendingCapture() {
        SecurityEvent event = buildEvent("req-006", "evt-006");
        store.complete(event);
        // No exception, no completed snapshot
        assertThat(store.consume("req-006")).isNull();
    }

    @Test
    @SuppressWarnings("unchecked")
    void captureAspectAcceptsSecurityDecisionSubclassWithoutClassNameMatching() {
        SecurityEvent event = buildEvent("req-aspect-subclass", "evt-aspect-subclass");
        SecurityDecisionContext subclass = new SecurityDecisionContext(event, null, null, List.of()) {
        };
        AIRequest<SecurityDecisionContext> request = mock(AIRequest.class);
        when(request.getContext()).thenReturn(subclass);
        SealedEvidencePromptCaptureAspect aspect = new SealedEvidencePromptCaptureAspect(store);

        aspect.capturePromptGenerationResult(request, "context", "metadata", mockPromptResult());
        store.complete(event);

        assertThat(store.consume("req-aspect-subclass")).isNotNull();
    }
    @Test
    void typedAdapterSupportsSecurityDecisionSubclass() {
        SecurityEvent event = buildEvent("req-subclass", "evt-subclass");
        SecurityDecisionContext subclass = new SecurityDecisionContext(event, null, null, List.of()) {
        };

        store.capture(new SecurityDecisionCaptureContextAdapter(subclass, mockPromptResult()));
        store.complete(event);

        assertThat(store.consume("req-subclass")).isNotNull();
    }

    @Test
    void ttlExpiresPendingAndCompletedSnapshots() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-15T00:00:00Z"));
        store = new SealedEvidencePromptTraceStore(
                null,
                Runnable::run,
                new VerificationCaptureStoreOptions(Duration.ofSeconds(1), 2, 2),
                clock);
        SecurityEvent completed = buildEvent("req-expired-completed", "evt-expired-completed");
        store.capture(mockContext(completed, mockPromptResult()));
        store.complete(completed);
        clock.advance(Duration.ofSeconds(2));
        assertThat(store.find("req-expired-completed")).isNull();

        SecurityEvent pending = buildEvent("req-expired-pending", "evt-expired-pending");
        store.capture(mockContext(pending, mockPromptResult()));
        clock.advance(Duration.ofSeconds(2));
        assertThat(store.consume("req-expired-pending")).isNull();
    }

    @Test
    void maximumCountsEvictOldestPendingAndCompletedSnapshots() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-15T00:00:00Z"));
        store = new SealedEvidencePromptTraceStore(
                null,
                Runnable::run,
                new VerificationCaptureStoreOptions(Duration.ofHours(1), 2, 2),
                clock);
        for (int index = 1; index <= 3; index++) {
            SecurityEvent event = buildEvent("req-completed-" + index, "evt-completed-" + index);
            store.capture(mockContext(event, mockPromptResult()));
            store.complete(event);
            clock.advance(Duration.ofSeconds(1));
        }
        assertThat(store.find("req-completed-1")).isNull();
        assertThat(store.find("req-completed-2")).isNotNull();
        assertThat(store.find("req-completed-3")).isNotNull();

        for (int index = 1; index <= 3; index++) {
            SecurityEvent event = buildEvent("req-pending-" + index, "evt-pending-" + index);
            store.capture(mockContext(event, mockPromptResult()));
            clock.advance(Duration.ofSeconds(1));
        }
        assertThat(store.consume("req-pending-1")).isNull();
        assertThat(store.consume("req-pending-2")).isNotNull();
        assertThat(store.consume("req-pending-3")).isNotNull();
    }

    @Test
    void duplicateRequestIdReplacesOlderCompletedSnapshotWithoutLeak() {
        SecurityEvent first = buildEvent("req-duplicate", "evt-duplicate-1");
        PromptGenerationResult firstPrompt = mockPromptResult();
        when(firstPrompt.getUserPrompt()).thenReturn("first prompt");
        store.capture(mockContext(first, firstPrompt));
        store.complete(first);

        SecurityEvent second = buildEvent("req-duplicate", "evt-duplicate-2");
        PromptGenerationResult secondPrompt = mockPromptResult();
        when(secondPrompt.getUserPrompt()).thenReturn("second prompt");
        store.capture(mockContext(second, secondPrompt));
        store.complete(second);

        assertThat(store.consume("req-duplicate").userPrompt()).isEqualTo("second prompt");
        assertThat(store.consume("req-duplicate")).isNull();
    }

    @Test
    void rejectedExecutorDoesNotRetainSnapshotAfterShutdown() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.shutdownNow();
        store = new SealedEvidencePromptTraceStore(
                null,
                executor,
                VerificationCaptureStoreOptions.defaults(),
                Clock.systemUTC());
        SecurityEvent event = buildEvent("req-shutdown", "evt-shutdown");

        assertThatThrownBy(() -> store.capture(mockContext(event, mockPromptResult())))
                .isInstanceOf(RejectedExecutionException.class);
        assertThat(executor.isShutdown()).isTrue();
        assertThat(store.consume("req-shutdown")).isNull();
    }
    private SecurityEvent buildEvent(String requestId, String eventId) {
        SecurityEvent event = SecurityEvent.builder().build();
        event.setEventId(eventId);
        Map<String, Object> meta = new HashMap<>();
        meta.put("requestId", requestId);
        event.setMetadata(meta);
        return event;
    }

    private VerificationCaptureContext mockContext(SecurityEvent event, PromptGenerationResult promptResult) {
        VerificationCaptureContext context = mock(VerificationCaptureContext.class);
        when(context.securityEvent()).thenReturn(event);
        when(context.relatedDocuments()).thenReturn(List.of());
        when(context.promptExecution()).thenReturn(promptResult);
        return context;
    }

    private static final class MutableClock extends Clock {
        private Instant current;

        private MutableClock(Instant current) {
            this.current = current;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }

        private void advance(Duration duration) {
            current = current.plus(duration);
        }
    }
    private PromptGenerationResult mockPromptResult() {
        PromptGenerationResult result = mock(PromptGenerationResult.class);
        when(result.getSystemPrompt()).thenReturn("system prompt");
        when(result.getUserPrompt()).thenReturn("user prompt");
        when(result.getRawSystemPrompt()).thenReturn("raw system");
        when(result.getRawUserPrompt()).thenReturn("raw user");

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("promptSourceContextLedger", "val");
        metadata.put("promptRawUserFieldLedger", "val");
        metadata.put("promptFinalUserFieldLedger", "val");
        metadata.put("promptUserFieldDiffLedger", "val");
        metadata.put("promptFieldStateLedger", List.of("item"));
        metadata.put("promptFieldStateSummary", "val");
        when(result.getMetadata()).thenReturn(metadata);

        return result;
    }

}
