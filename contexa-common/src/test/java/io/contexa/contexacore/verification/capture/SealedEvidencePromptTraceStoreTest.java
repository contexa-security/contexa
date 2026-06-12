package io.contexa.contexacore.verification.capture;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.springframework.ai.document.Document;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
        DomainContext context = mockContext(event);
        PromptGenerationResult promptResult = mockPromptResult();

        store.capture(context, promptResult);
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
        store.capture(mockContext(event), mockPromptResult());
        store.complete(event);

        SealedEvidencePromptSnapshot first = store.consume("req-002");
        SealedEvidencePromptSnapshot second = store.consume("req-002");

        assertThat(first).isNotNull();
        assertThat(second).isNull();
    }

    @Test
    void pendingSnapshotCanBeConsumedWhenLayer1CompletionWasNotObserved() {
        SecurityEvent event = buildEvent("req-003", "evt-003");
        store.capture(mockContext(event), mockPromptResult());
        // Not calling complete()

        SealedEvidencePromptSnapshot snapshot = store.consume("req-003");

        assertThat(snapshot).isNotNull();
        assertThat(snapshot.requestId()).isEqualTo("req-003");
        assertThat(store.consume("req-003")).isNull();
    }

    @Test
    void findDoesNotRemoveSnapshot() {
        SecurityEvent event = buildEvent("req-004", "evt-004");
        store.capture(mockContext(event), mockPromptResult());
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
        store.capture(mockContext(event), null);
        // No exception
    }

    @Test
    void completeIgnoresEventWithoutPendingCapture() {
        SecurityEvent event = buildEvent("req-006", "evt-006");
        store.complete(event);
        // No exception, no completed snapshot
        assertThat(store.consume("req-006")).isNull();
    }

    private SecurityEvent buildEvent(String requestId, String eventId) {
        SecurityEvent event = SecurityEvent.builder().build();
        event.setEventId(eventId);
        Map<String, Object> meta = new HashMap<>();
        meta.put("requestId", requestId);
        event.setMetadata(meta);
        return event;
    }

    private DomainContext mockContext(SecurityEvent event) {
        return new TestDomainContext(event);
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

    private static class TestDomainContext extends DomainContext {
        private final SecurityEvent securityEvent;
        private final Object sessionContext = new Object();
        private final Object behaviorAnalysis = new Object();
        private final List<Document> relatedDocuments = List.of();

        public TestDomainContext(SecurityEvent securityEvent) {
            super();
            this.securityEvent = securityEvent;
        }

        @Override
        public String getDomainType() {
            return "TEST";
        }
    }
}
