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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Layer1ContextualStrategyTest {

    @Mock
    private PipelineOrchestrator pipelineOrchestrator;

    private Layer1ContextualStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new Layer1ContextualStrategy(
                null,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                new TieredStrategyProperties()
        );
    }

    @Test
    @DisplayName("evaluate should return shouldEscalate=false when pipeline decides ALLOW")
    void evaluate_allowDecision_shouldEscalateFalse() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.1);
        response.setConfidence(0.9);
        response.setAction("ALLOW");
        response.setReasoning("Normal activity");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isFalse();
        assertThat(assessment.getAction()).isEqualTo("ALLOW");
        assertThat(assessment.getStrategyName()).isEqualTo("Layer1-Contextual");
        assertThat(assessment.getLlmAuditConfidence()).isEqualTo(0.9);
    }

    @Test
    @DisplayName("evaluate should return shouldEscalate=true when pipeline decides ESCALATE")
    void evaluate_escalateDecision_shouldEscalateTrue() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.7);
        response.setConfidence(0.5);
        response.setAction("ESCALATE");
        response.setReasoning("Suspicious patterns detected");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isTrue();
        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
        assertThat(assessment.getRecommendedActions()).contains("ESCALATE_TO_EXPERT");
    }

    @Test
    @DisplayName("evaluate should fallback to ESCALATE when pipeline fails")
    void evaluate_pipelineFailure_fallbackToEscalate() {
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isTrue();
        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
        assertThat(assessment.getRecommendedActions()).contains("ESCALATE_TO_EXPERT");
    }

    @Test
    @DisplayName("getLayerName should return Layer1")
    void getLayerName_returnsLayer1() {
        assertThat(strategy.getStrategyName()).isEqualTo("Layer1");
    }

    @Test
    @DisplayName("RAG summary 생성이 실패해도 빈 relatedDocuments로 계속 진행하고 prompt 분석은 유지되어야 한다")
    void analyzeWithContext_ragSummaryFailure_shouldContinueWithEmptyRelatedDocuments() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        PromptContextAuthorizationService authorizationService = mock(PromptContextAuthorizationService.class);
        Document brokenDocument = mock(Document.class);

        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class))).thenReturn(List.of(brokenDocument));
        lenient().when(authorizationService.authorize(any(), any(), ArgumentMatchers.<List<Document>>any()))
                .thenReturn(new AuthorizedPromptContext(
                        List.of(brokenDocument),
                        1,
                        1,
                        0,
                        "security_investigation",
                        List.of()));
        when(brokenDocument.getMetadata()).thenThrow(new IllegalStateException("broken metadata"));

        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.12);
        response.setConfidence(0.88);
        response.setAction("ALLOW");
        response.setReasoning("Continue with empty memory context");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        Layer1ContextualStrategy ragTolerantStrategy = new Layer1ContextualStrategy(
                vectorService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                null,
                null,
                null,
                authorizationService,
                null,
                pipelineOrchestrator,
                new TieredStrategyProperties()
        );

        SecurityEvent event = buildTestEvent();

        ThreatAssessment assessment = ragTolerantStrategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.getAction()).isEqualTo("ALLOW");
        assertThat(event.getMetadata()).containsEntry("ragUnavailable", true);
        assertThat(event.getMetadata()).containsEntry("relatedDocumentsCount", 0);
        assertThat(event.getMetadata()).containsKey("ragFailureType");
        assertThat(event.getMetadata()).containsKey("ragFailureMessage");
        verify(pipelineOrchestrator).execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));
    }

    @Test
    @DisplayName("evaluate should preserve RAG candidate and denied counts when authorization filters all documents")
    void analyzeWithContext_permissionFilteredRag_shouldPreserveSearchLedgerMetadata() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        PromptContextAuthorizationService authorizationService = mock(PromptContextAuthorizationService.class);
        Document deniedDocument = new Document(
                "User accessed a previous resource.",
                Map.of(
                        "documentType", "behavior",
                        "userId", "user-001",
                        "retrievalPurpose", "security_investigation",
                        "accessScope", "USER"));

        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class))).thenReturn(List.of(deniedDocument));
        when(authorizationService.authorize(any(), any(), ArgumentMatchers.<List<Document>>any()))
                .thenReturn(new AuthorizedPromptContext(
                        List.of(),
                        1,
                        0,
                        1,
                        "security_investigation",
                        List.of("DENIED_TENANT_SCOPE")));
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.22);
        response.setConfidence(0.77);
        response.setAction("ALLOW");
        response.setReasoning("Continue without unauthorized memory context");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        Layer1ContextualStrategy ragFilteredStrategy = new Layer1ContextualStrategy(
                vectorService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                null,
                null,
                null,
                authorizationService,
                null,
                pipelineOrchestrator,
                new TieredStrategyProperties()
        );

        SecurityEvent event = buildTestEvent();

        ThreatAssessment assessment = ragFilteredStrategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "PERMISSION_FILTERED")
                .containsEntry("ragAbsenceReason", "PERMISSION_FILTER_EXCLUDED")
                .containsEntry("ragProjectionState", "PERMISSION_FILTERED_DECLARED")
                .containsEntry("ragCandidateDocumentCount", 1)
                .containsEntry("ragAuthorizedDocumentCount", 0)
                .containsEntry("ragDeniedDocumentCount", 1)
                .containsEntry("ragPermissionFiltered", true)
                .containsEntry("requestedDocumentCount", 1)
                .containsEntry("allowedDocumentCount", 0)
                .containsEntry("deniedDocumentCount", 1)
                .containsEntry("relatedDocumentCount", 0);
    }

    @Test
    @DisplayName("RAG fallback should prefer same-user baseline evidence before organization support")
    void analyzeWithContext_userBaselineFallback_shouldNotBeMaskedByOrganizationSupport() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        Document currentUserDocument = new Document(
                "User accessed a previous public resource.",
                Map.of(
                        "documentType", "behavior",
                        "userId", "user-001",
                        "tenantId", "demo",
                        "organizationId", "demo-org",
                        "retrievalPurpose", "security_investigation",
                        "accessScope", "USER"));

        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class)))
                .thenReturn(List.of())
                .thenReturn(List.of(currentUserDocument))
                .thenReturn(List.of())
                .thenReturn(List.of());

        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.18);
        response.setConfidence(0.82);
        response.setAction("ALLOW");
        response.setReasoning("Use authorized user baseline context");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        Layer1ContextualStrategy ragStrategy = new Layer1ContextualStrategy(
                vectorService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                new TieredStrategyProperties()
        );

        SecurityEvent event = buildTestEvent();
        event.getMetadata().put("tenantId", "demo");
        event.getMetadata().put("organizationId", "demo-org");

        ThreatAssessment assessment = ragStrategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("ragProjectionState", "PROJECTED")
                .containsEntry("ragCandidateDocumentCount", 1)
                .containsEntry("ragAuthorizedDocumentCount", 1)
                .containsEntry("ragDeniedDocumentCount", 0)
                .containsEntry("ragPermissionFiltered", false)
                .containsEntry("relatedDocumentCount", 1);
    }

    @Test
    @DisplayName("RAG search timeout should preserve timeout metadata and continue analysis")
    void analyzeWithContext_ragTimeout_shouldContinueWithEmptyRelatedDocuments() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        PromptContextAuthorizationService authorizationService = mock(PromptContextAuthorizationService.class);
        TieredStrategyProperties properties = new TieredStrategyProperties();
        AtomicBoolean interrupted = new AtomicBoolean(false);
        properties.getLayer1().getTimeout().setRagMs(50);

        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class))).thenAnswer(invocation -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException interruptedException) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
            }
            return List.of();
        });
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.18);
        response.setConfidence(0.82);
        response.setAction("ALLOW");
        response.setReasoning("Continue without waiting for slow memory lookup");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ExecutorService ragExecutor = new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>());
        try {
            Layer1ContextualStrategy ragTimeoutStrategy = new Layer1ContextualStrategy(
                    vectorService,
                    null,
                    new SecurityEventEnricher(),
                    new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    authorizationService,
                    null,
                    pipelineOrchestrator,
                    properties,
                    null,
                    ragExecutor
            );

            SecurityEvent event = buildTestEvent();

            ThreatAssessment assessment = ragTimeoutStrategy.evaluate(event);

            assertThat(assessment).isNotNull();
            assertThat(assessment.getAction()).isEqualTo("ALLOW");
            assertThat(event.getMetadata()).containsEntry("ragUnavailable", true);
            assertThat(event.getMetadata()).containsEntry("ragTimedOut", true);
            assertThat(event.getMetadata()).containsEntry("ragTimeoutMs", 50L);
            assertThat(event.getMetadata()).containsEntry("relatedDocumentsCount", 0);
            assertThat(event.getMetadata()).containsKey("ragFailureType");
            assertThat(event.getMetadata()).containsKey("ragFailureMessage");
            assertThat(interrupted.get()).isTrue();
            verify(pipelineOrchestrator).execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));
        } finally {
            ragExecutor.shutdownNow();
        }
    }

    private SecurityEvent buildTestEvent() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "GET");
        metadata.put("requestPath", "/api/data");

        return SecurityEvent.builder()
                .eventId("test-event-layer1")
                .userId("user-001")
                .sessionId("session-001")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .timestamp(LocalDateTime.now())
                .metadata(metadata)
                .build();
    }
}
