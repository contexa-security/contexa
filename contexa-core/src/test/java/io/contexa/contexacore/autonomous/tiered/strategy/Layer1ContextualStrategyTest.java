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

import io.contexa.contexacore.autonomous.context.support.PastRecordGroup;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.context.support.PastRecordScope;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import org.mockito.ArgumentCaptor;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import java.time.ZoneId;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.VectorOperations;
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

    /** W4-3: the reason codes of the model response reach the assessment. */
    @Test
    void evaluate_keepsTheReasonCodesOfTheResponse() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("CHALLENGE");
        response.setReasoning("The export time differs from usual.");
        response.setReasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1")));
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment.getReasonCodes()).containsExactly(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1"));
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
    @DisplayName("evaluate should preserve LLM ALLOW when only prompt-quality verification is required")
    void evaluate_promptQualityVerificationRequired_shouldNotConstrainAllow() {
        SecurityEvent event = buildTestEvent();
        event.getMetadata().put("protectableVerificationRequired", true);
        event.getMetadata().put("mfaVerified", false);
        event.getMetadata().put("authorizationEffect", "ALLOW");
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("The model proposed ALLOW.");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment.getAction()).isEqualTo("ALLOW");
        assertThat(assessment.getAutonomousAction()).isEqualTo("ALLOW");
        assertThat(assessment.getAutonomyConstraintApplied()).isNull();
        assertThat(assessment.getAutonomyConstraintReasons()).isEmpty();
        assertThat(assessment.getAutonomyConstraintPolicy()).isNull();
        assertThat(assessment.getAutonomyConstraintSource()).isNull();
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
    @DisplayName("RAG summary failure should continue with empty related documents")
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

        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getRag().setMultiQuerySearchEnabled(true);
        properties.getLayer1().getRag().setSupportingSearchEnabled(true);

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
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getRag().setMultiQuerySearchEnabled(true);
        properties.getLayer1().getRag().setSupportingSearchEnabled(true);

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

        // The four queries run in parallel, so the answer goes by content: one query filtered to this user gets the
        // document, once; the supporting query leaves this user's documents out and must not be the one that gets it.
        AtomicBoolean userEvidenceGiven = new AtomicBoolean(false);
        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class))).thenAnswer(invocation -> {
            SearchRequest request = invocation.getArgument(0);
            boolean userScoped = request.getFilterExpression() != null
                    && request.getFilterExpression().toString().contains("user-001");
            return userScoped && userEvidenceGiven.compareAndSet(false, true)
                    ? List.of(currentUserDocument)
                    : List.of();
        });

        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getRag().setMultiQuerySearchEnabled(true);
        properties.getLayer1().getRag().setSupportingSearchEnabled(true);

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
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                properties
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
    @DisplayName("Runtime RAG timeout should return after the hot-path wait and continue cache warmup")
    void analyzeWithContext_runtimeRagTimeout_shouldCancelSlowLookup() throws InterruptedException {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        PromptContextAuthorizationService authorizationService = mock(PromptContextAuthorizationService.class);
        TieredStrategyProperties properties = new TieredStrategyProperties();
        AtomicBoolean interrupted = new AtomicBoolean(false);
        properties.getLayer1().getTimeout().setRagMs(500);
        properties.getLayer1().getTimeout().setInteractiveRagWaitMs(50);

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
            assertThat(event.getMetadata()).containsEntry("ragInteractiveWaitMs", 50L);
            assertThat(event.getMetadata()).containsEntry("ragFullTimeoutMs", 500L);
            assertThat(event.getMetadata()).containsEntry("ragRuntimeBudgetPolicy", "INTERACTIVE_WAIT_WITH_BACKGROUND_WARMUP");
            assertThat(event.getMetadata()).containsEntry("ragBackgroundWarmup", true);
            assertThat(event.getMetadata()).containsEntry("relatedDocumentsCount", 0);
            assertThat(event.getMetadata()).containsKey("ragFailureType");
            assertThat(event.getMetadata()).containsKey("ragFailureMessage");
            Thread.sleep(25L);
            assertThat(interrupted.get()).isFalse();
            verify(pipelineOrchestrator).execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));
        } finally {
            ragExecutor.shutdownNow();
        }
    }

    /**
     * R4-L3: the former verification markers (the boundary mode, a probe path) are event text, so such an event waits for
     * its past records only as long as any interactive request does.
     */
    @Test
    void anEventNamingTheFormerVerificationMarkersWaitsOnlyTheInteractiveTime() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        PromptContextAuthorizationService authorizationService = mock(PromptContextAuthorizationService.class);
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setRagMs(50);
        properties.getLayer1().getTimeout().setInteractiveRagWaitMs(10);
        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class))).thenAnswer(invocation -> {
            Thread.sleep(200);
            return List.of();
        });
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.18);
        response.setConfidence(0.82);
        response.setAction("ALLOW");
        response.setReasoning("Interactive wait");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));
        ExecutorService ragExecutor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>());
        try {
            Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                    vectorService, null, new SecurityEventEnricher(),
                    new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                    null, null, null, null, null, null, null, authorizationService, null, pipelineOrchestrator,
                    properties, null, ragExecutor);
            SecurityEvent event = buildTestEvent();
            event.getMetadata().put("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME");
            event.getMetadata().put("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");

            strategy.evaluate(event);

            assertThat(event.getMetadata()).containsEntry("ragInteractiveWaitMs", 10L);
            assertThat(event.getMetadata()).containsEntry("ragFullTimeoutMs", 50L);
        } finally {
            ragExecutor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Inner vector timeout must retain its recorded budget-expired state")
    void analyzeWithContext_innerVectorTimeoutPreservesRecordedBudgetExpiry() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        PromptContextAuthorizationService authorizationService = mock(PromptContextAuthorizationService.class);
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setRagMs(8000);
        // R4-L3: the full wait comes from the configuration (interactive wait = full budget), not from event text.
        properties.getLayer1().getTimeout().setInteractiveRagWaitMs(8000);

        when(vectorService.searchSimilar(ArgumentMatchers.any(SearchRequest.class)))
                .thenThrow(new VectorOperations.VectorStoreException("Vector store similarity search timed out after 4000ms"));
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.18);
        response.setConfidence(0.82);
        response.setAction("ALLOW");
        response.setReasoning("The full budget keeps the timeout semantics");
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
            assertThat(event.getMetadata()).containsEntry("ragUnavailable", false);
            assertThat(event.getMetadata()).containsEntry("ragTimedOut", true);
            assertThat(event.getMetadata()).containsEntry("ragTimeoutMs", 8000L);
            assertThat(event.getMetadata()).containsEntry("ragInteractiveWaitMs", 8000L);
            assertThat(event.getMetadata()).containsEntry("ragFullTimeoutMs", 8000L);
            assertThat(event.getMetadata()).doesNotContainKey("ragBackgroundWarmup");
            assertThat(event.getMetadata()).containsEntry("ragRetrievalState", "BUDGET_EXPIRED");
            assertThat(event.getMetadata()).containsEntry("ragProjectionState", "BUDGET_EXPIRED_DECLARED");
            assertThat(event.getMetadata()).containsEntry("ragAbsenceReason", "BUDGET_EXPIRED");
            verify(pipelineOrchestrator).execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));
        } finally {
            ragExecutor.shutdownNow();
        }
    }
    @Test
    @DisplayName("the strategy reads the ids a session had before a step-up check from the context store (P2 correction 5)")
    void previousSessionIds_comeFromTheContextStore() {
        InMemorySecurityContextDataStore dataStore = new InMemorySecurityContextDataStore();
        Layer1ContextualStrategy sessionStrategy = new Layer1ContextualStrategy(
                null,
                dataStore,
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
        dataStore.addSessionDecision("session-old", "decision-1");

        dataStore.moveSessionRecords("session-old", "session-new");

        assertThat(sessionStrategy.previousSessionIds("session-new")).containsExactly("session-old");
        assertThat(sessionStrategy.previousSessionIds("session-other")).isEmpty();
    }

    @Test
    @DisplayName("a cached session reads what the session stored since and its current sign-in method (W1-11)")
    void evaluate_cachedSessionReadsWhatTheSessionStoredSince() {
        InMemorySecurityContextDataStore dataStore = new InMemorySecurityContextDataStore();
        Layer1ContextualStrategy sessionStrategy = new Layer1ContextualStrategy(
                null,
                dataStore,
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
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("Normal activity");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        dataStore.addSessionAction("session-001", "03:15 | MFA_LOGIN (multi-factor sign-in) | 192.168.1.100");
        SecurityEvent first = buildTestEvent();
        first.setEventId("event-session-first");
        first.getMetadata().put("authMethod", "PASSWORD");
        sessionStrategy.evaluate(first);

        // The same refusal twice in one minute is two stored lines and must count twice.
        dataStore.addSessionAction("session-001", "03:16 | AUTHORIZATION_DENIED | GET /api/customers | 192.168.1.100");
        dataStore.addSessionAction("session-001", "03:16 | AUTHORIZATION_DENIED | GET /api/customers | 192.168.1.100");
        SecurityEvent second = buildTestEvent();
        second.setEventId("event-session-second");
        second.getMetadata().put("authMethod", "MFA");
        sessionStrategy.evaluate(second);

        ArgumentCaptor<SecurityDecisionRequest> requests = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator, times(2)).execute(requests.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        SecurityDecisionStandardPromptTemplate.SessionContext secondSession =
                requests.getAllValues().get(1).getContext().getSessionContext();
        assertThat(secondSession.getAuthMethod()).isEqualTo("MFA");
        assertThat(secondSession.getRecentActions()).first().asString().contains("MFA_LOGIN");
        assertThat(secondSession.getRecentActions())
                .filteredOn(action -> action.contains("AUTHORIZATION_DENIED"))
                .hasSize(2);
    }

    /**
     * W3-18: Layer1 fixes the event's bundle before it copies the event for the past record search, so a v20 request
     * reads its past records by the exact lookup on the copy and the prompt drawn later keeps the same bundle.
     */
    @Test
    void layer1FixesTheBundleBeforeItsPastRecordSearchAndAV20RequestReadsThemExactly() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        when(vectorService.pastRecordQuery()).thenReturn(new PastRecordQuery() {
            @Override
            public boolean available() {
                return true;
            }

            @Override
            public List<PastRecordGroup> groups(PastRecordScope scope) {
                return List.of(new PastRecordGroup("/api/data", "/api/data", "GET", 4, null));
            }

            @Override
            public List<Document> records(PastRecordScope scope, List<String> firstPaths, int limit) {
                return List.of();
            }
        });
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("Usual read");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));
        Layer1ContextualStrategy v20Strategy = new Layer1ContextualStrategy(
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
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                properties
        );
        SecurityEvent event = buildTestEvent();

        v20Strategy.evaluate(event);

        verify(vectorService, never()).searchSimilar(ArgumentMatchers.any(SearchRequest.class));
        assertThat(event.getMetadata())
                .containsEntry("promptBundleSelection.version", SecurityDecisionPromptBundles.V20.version())
                .containsEntry("ragSearchMode", "EXACT_PAST_RECORD_LOOKUP")
                .containsKey("ragPastRecordCounts");
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
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .metadata(metadata)
                .build();
    }
}




