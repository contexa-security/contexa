package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.*;
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
}
