package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityDecisionPostProcessorTest {

    @Mock
    private SecurityContextDataStore dataStore;

    @Mock
    private UnifiedVectorService unifiedVectorService;

    private SecurityDecisionPostProcessor postProcessor;

    @BeforeEach
    void setUp() {
        postProcessor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
    }

    @Test
    @DisplayName("updateSessionContext should call addSessionAction")
    void shouldCallAddSessionAction() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-1")
                .sessionId("session-1")
                .userId("user1")
                .sourceIp("10.0.0.1")
                .timestamp(LocalDateTime.of(2025, 1, 15, 10, 30))
                .build();

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.2)
                .build();

        // when
        postProcessor.updateSessionContext(event, decision);

        // then
        verify(dataStore).addSessionAction(eq("session-1"), anyString());
    }

    @Test
    @DisplayName("BLOCK decision should record risk score via setSessionRisk")
    void shouldRecordRiskScoreForBlockDecision() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-1")
                .sessionId("session-1")
                .build();

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.BLOCK)
                .riskScore(0.95)
                .build();

        // when
        postProcessor.updateSessionContext(event, decision);

        // then
        verify(dataStore).addSessionAction(eq("session-1"), anyString());
        verify(dataStore).setSessionRisk("session-1", 0.95);
    }

    @Test
    @DisplayName("ALLOW decision should store behavior document in vector DB")
    void shouldStoreBehaviorDocumentForAllow() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-1")
                .userId("user1")
                .sourceIp("10.0.0.1")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
                .timestamp(LocalDateTime.of(2025, 1, 15, 10, 30))
                .build();

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .build();

        // when
        postProcessor.storeInVectorDatabase(event, decision);

        // then
        ArgumentCaptor<Document> captor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(captor.capture());

        Document doc = captor.getValue();
        assertThat(doc.getMetadata().get("documentType")).isEqualTo("behavior");
    }

    @Test
    @DisplayName("BLOCK decision should store threat document in vector DB")
    void shouldStoreThreatDocumentForBlock() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-1")
                .userId("user1")
                .sourceIp("10.0.0.1")
                .timestamp(LocalDateTime.of(2025, 1, 15, 10, 30))
                .build();

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.BLOCK)
                .riskScore(0.95)
                .threatCategory("brute_force")
                .build();

        // when
        postProcessor.storeInVectorDatabase(event, decision);

        // then
        ArgumentCaptor<Document> captor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(captor.capture());

        Document doc = captor.getValue();
        assertThat(doc.getMetadata().get("documentType")).isEqualTo("threat");
        assertThat(doc.getMetadata().get("threatCategory")).isEqualTo("brute_force");
    }

    @Test
    @DisplayName("Null sessionId should skip session context update")
    void shouldSkipWhenSessionIdIsNull() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-1")
                .sessionId(null)
                .build();

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .build();

        // when
        postProcessor.updateSessionContext(event, decision);

        // then
        verify(dataStore, never()).addSessionAction(anyString(), anyString());
        verify(dataStore, never()).setSessionRisk(anyString(), any(double.class));
    }
}
