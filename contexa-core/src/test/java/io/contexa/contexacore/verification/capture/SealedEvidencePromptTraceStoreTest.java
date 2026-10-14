package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
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

        store.capture(decisionContext(event), promptResult);
        store.complete(event);

        SealedEvidencePromptSnapshot snapshot = store.consume("req-001");
        assertThat(snapshot).isNotNull();
        assertThat(snapshot.requestId()).isEqualTo("req-001");
        assertThat(snapshot.systemPrompt()).isEqualTo("system prompt");
        assertThat(snapshot.userPrompt()).isEqualTo("user prompt");
        assertThat(snapshot.metadata()).containsEntry("promptVersion", "v1");
    }

    @Test
    void consumeReturnNullForUnknownRequestId() {
        assertThat(store.consume("nonexistent")).isNull();
    }

    @Test
    void consumeRemovesSnapshotFromStore() {
        SecurityEvent event = buildEvent("req-002", "evt-002");
        store.capture(decisionContext(event), mockPromptResult());
        store.complete(event);

        SealedEvidencePromptSnapshot first = store.consume("req-002");
        SealedEvidencePromptSnapshot second = store.consume("req-002");

        assertThat(first).isNotNull();
        assertThat(second).isNull();
    }

    @Test
    void aSnapshotIsNotHandedOutBeforeLayer1Completed() {
        SecurityEvent event = buildEvent("req-003", "evt-003");
        store.capture(decisionContext(event), mockPromptResult());

        assertThat(store.consume("req-003")).isNull();

        store.complete(event);
        assertThat(store.consume("req-003")).isNotNull();
    }

    @Test
    void noCompletedSnapshotIsHandedOutUnderAnotherKey() {
        SecurityEvent event = buildEvent("req-010", "evt-010");
        event.getMetadata().put(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "trace-010");
        store.capture(decisionContext(event), mockPromptResult());
        store.complete(event);

        assertThat(store.consume("req-010")).isNull();
        assertThat(store.consume("trace-010")).isNotNull();
    }

    @Test
    void aFaultMarkedEventIsLeftAsItCame() {
        SecurityEvent event = buildEvent("req-011", "evt-011");
        event.getMetadata().put("pqaPromptFaultApplied", true);
        event.getMetadata().put("pqaPromptFaultScenario", "rag_scope_slot_fault");
        store.capture(decisionContext(event), mockPromptResult());

        assertThat(event.getMetadata()).containsEntry("pqaPromptFaultScenario", "rag_scope_slot_fault")
                .doesNotContainKey("pqaPromptFaultSource");
    }

    @Test
    void theSnapshotMetadataIsThePromptMetadataAsItCame() {
        SecurityEvent event = buildEvent("req-012", "evt-012");
        PromptGenerationResult promptResult = mockPromptResult();
        store.capture(decisionContext(event), promptResult);
        store.complete(event);

        SealedEvidencePromptSnapshot snapshot = store.consume("req-012");
        assertThat(snapshot.metadata().getClass().getSimpleName()).isNotEqualTo("LazyDelegatingMap");
        assertThat(snapshot.metadata()).isEqualTo(promptResult.getMetadata());
    }

    @Test
    void findDoesNotRemoveSnapshot() {
        SecurityEvent event = buildEvent("req-004", "evt-004");
        store.capture(decisionContext(event), mockPromptResult());
        store.complete(event);

        assertThat(store.find("req-004")).isNotNull();
        assertThat(store.find("req-004")).isNotNull();
    }

    @Test
    void captureIgnoresNullContext() {
        store.capture(null, mockPromptResult());
        // No exception
    }

    @Test
    void captureIgnoresNullPromptResult() {
        SecurityEvent event = buildEvent("req-005", "evt-005");
        store.capture(decisionContext(event), null);
        store.complete(event);
        assertThat(store.consume("req-005")).isNull();
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
    void ttlExpiresPendingAndCompletedSnapshots() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-15T00:00:00Z"));
        store = new SealedEvidencePromptTraceStore(new VerificationCaptureStoreOptions(Duration.ofSeconds(1), 2, 2), clock);
        SecurityEvent completed = buildEvent("req-expired-completed", "evt-expired-completed");
        store.capture(decisionContext(completed), mockPromptResult());
        store.complete(completed);
        clock.advance(Duration.ofSeconds(2));
        assertThat(store.find("req-expired-completed")).isNull();

        SecurityEvent pending = buildEvent("req-expired-pending", "evt-expired-pending");
        store.capture(decisionContext(pending), mockPromptResult());
        clock.advance(Duration.ofSeconds(2));
        store.complete(pending);
        assertThat(store.consume("req-expired-pending")).isNull();
    }

    @Test
    void maximumCountsEvictOldestPendingAndCompletedSnapshots() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-15T00:00:00Z"));
        store = new SealedEvidencePromptTraceStore(new VerificationCaptureStoreOptions(Duration.ofHours(1), 2, 2), clock);
        for (int index = 1; index <= 3; index++) {
            SecurityEvent event = buildEvent("req-completed-" + index, "evt-completed-" + index);
            store.capture(decisionContext(event), mockPromptResult());
            store.complete(event);
            clock.advance(Duration.ofSeconds(1));
        }
        assertThat(store.find("req-completed-1")).isNull();
        assertThat(store.find("req-completed-2")).isNotNull();
        assertThat(store.find("req-completed-3")).isNotNull();

        List<SecurityEvent> pending = new ArrayList<>();
        for (int index = 1; index <= 3; index++) {
            SecurityEvent event = buildEvent("req-pending-" + index, "evt-pending-" + index);
            store.capture(decisionContext(event), mockPromptResult());
            pending.add(event);
            clock.advance(Duration.ofSeconds(1));
        }
        store.complete(pending.get(0));
        assertThat(store.consume("req-pending-1")).isNull();
        store.complete(pending.get(1));
        assertThat(store.consume("req-pending-2")).isNotNull();
        store.complete(pending.get(2));
        assertThat(store.consume("req-pending-3")).isNotNull();
    }

    @Test
    void duplicateRequestIdReplacesOlderCompletedSnapshotWithoutLeak() {
        SecurityEvent first = buildEvent("req-duplicate", "evt-duplicate-1");
        PromptGenerationResult firstPrompt = mockPromptResult();
        when(firstPrompt.getUserPrompt()).thenReturn("first prompt");
        store.capture(decisionContext(first), firstPrompt);
        store.complete(first);

        SecurityEvent second = buildEvent("req-duplicate", "evt-duplicate-2");
        PromptGenerationResult secondPrompt = mockPromptResult();
        when(secondPrompt.getUserPrompt()).thenReturn("second prompt");
        store.capture(decisionContext(second), secondPrompt);
        store.complete(second);

        assertThat(store.consume("req-duplicate").userPrompt()).isEqualTo("second prompt");
        assertThat(store.consume("req-duplicate")).isNull();
    }

    private SecurityEvent buildEvent(String requestId, String eventId) {
        SecurityEvent event = SecurityEvent.builder().build();
        event.setEventId(eventId);
        Map<String, Object> meta = new HashMap<>();
        meta.put("requestId", requestId);
        event.setMetadata(meta);
        return event;
    }

    private SecurityDecisionContext decisionContext(SecurityEvent event) {
        SecurityDecisionContext context = mock(SecurityDecisionContext.class);
        when(context.getSecurityEvent()).thenReturn(event);
        when(context.getRelatedDocuments()).thenReturn(List.of());
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
        metadata.put("promptVersion", "v1");
        when(result.getMetadata()).thenReturn(metadata);
        return result;
    }
}
