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

import java.time.Instant;
import java.time.ZoneId;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
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
import static org.mockito.ArgumentMatchers.any;

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
                .timestamp(LocalDateTime.of(2026, 3, 23, 10, 15).atZone(ZoneId.systemDefault()).toInstant())
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
    void updateSessionContextLeavesTheDecisionHistoryToTheRecorderOfTheFinalOutcome() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        Instant at = LocalDateTime.of(2026, 3, 23, 10, 15).atZone(ZoneId.systemDefault()).toInstant();
        SecurityEvent event = SecurityEvent.builder()
                .sessionId("session-1")
                .userId("alice")
                .description("POST /payments")
                .timestamp(at)
                .build();
        event.addMetadata("requestPath", "/payments");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("actionFamily", "WRITE");

        processor.updateSessionContext(event, SecurityDecision.builder().action(ZeroTrustAction.CHALLENGE).build());

        // The session keeps its request summary line. The decision history holds one line per request with its
        // final outcome, recorded where that outcome is known (W2-7): an analysis layer that escalates is no outcome.
        verify(dataStore).addSessionAction(eq("session-1"), contains("observed challenge"));
        verify(dataStore, never()).addSessionDecision(any(), any());
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
                .timestamp(LocalDateTime.of(2026, 3, 30, 9, 24).atZone(ZoneId.systemDefault()).toInstant())
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
    void storeBehaviorDocumentKeepsTheScoresInTheMetadataOnly() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-behavior-001")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("203.0.113.10")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /payments")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 30).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/payments");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("organizationId", "demo-org");
        event.addMetadata("authMethod", "password");
        event.addMetadata("authenticationType", "UsernamePasswordAuthenticationToken");
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

        // W3-18: the decision and its scores are not embedded; they stay in the metadata, which the exact lookup reads.
        assertThat(document.getText()).doesNotContain("Decision:", "proposedAction", "riskScore", "confidence",
                "analysisLayer");
        assertThat(document.getText()).doesNotContain("Reasoning:");
        assertThat(document.getText()).doesNotContain("LearnedAfter:");
        assertThat(document.getText()).doesNotContain("Current context is consistent with recent allowed protectable access.");
        assertThat(document.getMetadata()).containsEntry("riskScore", 0.10);
        assertThat(document.getMetadata()).containsEntry("confidence", 0.70);
        assertThat(document.getMetadata()).containsEntry("llmAuditRiskScore", 0.10);
        assertThat(document.getMetadata()).containsEntry("llmAuditConfidence", 0.70);
        assertThat(document.getMetadata()).containsEntry("tenantId", "demo");
        assertThat(document.getMetadata()).containsEntry("organizationId", "demo-org");
        assertThat(document.getMetadata()).containsEntry("authenticationType", "PASSWORD");
    }

    @Test
    void aRequestLearnedAfterAVerificationSaysSoInItsPastRecord() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-verified-001")
                .userId("alice")
                .sourceIp("10.40.12.7")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
                .description("POST /api/projects/PLM-OPS/exports")
                .timestamp(LocalDateTime.of(2026, 9, 30, 3, 17).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/PLM-OPS/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("verifiedBy", "STEP_UP");
        event.addMetadata("verificationWeight", 0.5);
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.05)
                .confidence(0.95)
                .reasoning("Allowed after the user passed the step-up verification the decision asked for")
                .build();
        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        // W5-2: the record states that the request was allowed only after its verification, and at what weight.
        assertThat(documentCaptor.getValue().getText()).contains("LearnedAfter: STEP_UP verification at weight 0.5");
        assertThat(documentCaptor.getValue().getMetadata()).containsEntry("verifiedBy", "STEP_UP")
                .containsEntry("verificationWeight", 0.5);
    }

    @Test
    void storeInVectorDatabaseShouldRecordTheRequestsActionFamilyNotTheDecision() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-export-001")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("203.0.113.10")
                .description("POST /api/projects/GB-500/exports")
                .timestamp(LocalDateTime.of(2026, 3, 30, 9, 24).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments");
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.ALLOW)
                .riskScore(0.2)
                .confidence(0.8)
                .reasoning("Authorization allows access with a limited baseline.")
                .processingLayer(1)
                .build();
        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        Map<String, Object> metadata = documentCaptor.getValue().getMetadata();
        // The past record names the export the way the current request does (W2-1).
        assertThat(metadata.get("actionFamily")).isEqualTo("EXPORT");
        assertThat(metadata.get("actionFamilySource")).isEqualTo("inferred:protectableMethod");
    }

    @Test
    void storeInVectorDatabaseShouldRecordTheHostsUrlTemplateAsThePathFamily() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-export-002")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("203.0.113.10")
                .description("POST /api/projects/GB-500/exports")
                .timestamp(LocalDateTime.of(2026, 3, 30, 9, 24).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("protectableResourceUrl", "/api/projects/{projectKey}/exports");
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.ALLOW)
                .riskScore(0.2)
                .confidence(0.8)
                .processingLayer(1)
                .build();
        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        Map<String, Object> metadata = documentCaptor.getValue().getMetadata();
        // The past record names the kind of request the way the current request does, not the project (W2-2).
        assertThat(metadata.get("requestPath")).isEqualTo("/api/projects/GB-500/exports");
        assertThat(metadata.get("pathFamily")).isEqualTo("/api/projects/{projectKey}/exports");
    }

    @Test
    void aPastRecordKeepsTheRequestsItemCountAndNetworkZone() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-items-zone")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("10.40.12.10")
                .description("POST /api/projects/PLM-OPS/exports")
                .timestamp(LocalDateTime.of(2026, 9, 26, 10, 30).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/PLM-OPS/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestItems", 23);
        event.addMetadata("networkZone", "CORPORATE");
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.ALLOW)
                .processingLayer(1)
                .build();
        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        assertThat(documentCaptor.getValue().getMetadata())
                .containsEntry("requestItems", 23)
                .containsEntry("networkZone", "CORPORATE");
    }

    /** A host may state the zone in the canonical context only; the record keeps the values the decision used. */
    @Test
    void aPastRecordKeepsTheItemCountAndNetworkZoneOfTheCanonicalContextTheDecisionUsed() {
        SecurityDecisionPostProcessor processor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-canonical-zone")
                .sessionId("session-1")
                .userId("alice")
                .sourceIp("10.40.12.10")
                .description("POST /api/projects/GB-500/exports")
                .timestamp(LocalDateTime.of(2026, 9, 30, 3, 17).atZone(ZoneId.systemDefault()).toInstant())
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder()
                .location(CanonicalSecurityContext.Location.builder().networkZone("CORPORATE").build())
                .resource(CanonicalSecurityContext.Resource.builder().requestedItems(4831).build())
                .build());
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.ALLOW)
                .processingLayer(1)
                .build();
        doNothing().when(unifiedVectorService).storeDocument(any(Document.class));

        processor.storeInVectorDatabase(event, decision);

        ArgumentCaptor<Document> documentCaptor = ArgumentCaptor.forClass(Document.class);
        verify(unifiedVectorService).storeDocument(documentCaptor.capture());
        assertThat(documentCaptor.getValue().getMetadata())
                .containsEntry("requestItems", 4831)
                .containsEntry("networkZone", "CORPORATE");
    }
}
