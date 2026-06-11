/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

    @Test
    void storeBehaviorDocumentShouldKeepTextAndMetadataScoresAligned() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-behavior-001")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("203.0.113.10")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /payments")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 30))
                .build();
        event.addMetadata("requestPath", "/payments");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("organizationId", "demo-org");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("isSensitiveResource", true);
        event.addMetadata("recentRequestCount", 4);

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.ALLOW)
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(0.10)
                .llmAuditConfidence(0.70)
                .reasoning("Current context is consistent with recent allowed protectable access.")
                .processingLayer(1)
                .build();

        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        Document document = documentCaptor.getValue();

        assertThat(document.getText()).contains("riskScore=0.10");
        assertThat(document.getText()).contains("confidence=0.70");
        assertThat(document.getText()).contains("llmAuditRiskScore=0.10");
        assertThat(document.getText()).contains("llmAuditConfidence=0.70");
        assertThat(document.getMetadata()).containsEntry("riskScore", 0.10);
        assertThat(document.getMetadata()).containsEntry("confidence", 0.70);
        assertThat(document.getMetadata()).containsEntry("llmAuditRiskScore", 0.10);
        assertThat(document.getMetadata()).containsEntry("llmAuditConfidence", 0.70);
        assertThat(document.getMetadata()).containsEntry("tenantId", "demo");
        assertThat(document.getMetadata()).containsEntry("organizationId", "demo-org");
    }
}
