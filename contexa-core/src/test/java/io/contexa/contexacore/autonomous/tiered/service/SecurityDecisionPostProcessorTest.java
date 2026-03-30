package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityDecisionPostProcessorTest {

    @Mock
    private SecurityContextDataStore dataStore;

    @Mock
    private UnifiedVectorService unifiedVectorService;

    @Test
    void updateSessionContextDoesNotPersistAuditRiskScore() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .sessionId("session-1")
                .userId("alice")
                .description("POST /payments")
                .timestamp(LocalDateTime.of(2026, 3, 23, 10, 15))
                .build();
        event.addMetadata("requestPath", "/payments");
        event.addMetadata("httpMethod", "POST");

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.BLOCK)
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(0.98)
                .llmAuditConfidence(0.91)
                .build();

        processor.updateSessionContext(event, decision);

        verify(dataStore).addSessionAction(eq("session-1"), contains("observed block"));
        verify(dataStore, never()).setSessionRisk(anyString(), anyDouble());
    }

    @Test
    void storeInVectorDatabaseShouldFallbackToAuditScoresWhenEffectiveScoresAreNull() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-ambiguous-001")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("203.0.113.10")
                .description("POST /payments")
                .timestamp(LocalDateTime.of(2026, 3, 30, 9, 24))
                .build();
        event.addMetadata("requestPath", "/payments");
        event.addMetadata("httpMethod", "POST");

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ESCALATE)
                .autonomousAction(ZeroTrustAction.ESCALATE)
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(0.72)
                .llmAuditConfidence(0.61)
                .reasoning("Critical decision context is incomplete.")
                .processingLayer(1)
                .build();

        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        Map<String, Object> metadata = documentCaptor.getValue().getMetadata();
        assertThat(metadata.get("documentType")).isEqualTo("ambiguous");
        assertThat(metadata.get("riskScore")).isEqualTo(0.72);
        assertThat(metadata.get("llmAuditRiskScore")).isEqualTo(0.72);
        assertThat(metadata.get("confidence")).isEqualTo(0.61);
        assertThat(metadata.get("llmAuditConfidence")).isEqualTo(0.61);
    }
}
