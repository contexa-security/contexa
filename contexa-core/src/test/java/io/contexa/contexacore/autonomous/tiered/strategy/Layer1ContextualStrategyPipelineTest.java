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

import java.time.ZoneId;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Layer1ContextualStrategyPipelineTest {

    @Mock
    private PipelineOrchestrator pipelineOrchestrator;

    @Test
    @DisplayName("Layer1 파이프라인은 표준 SecurityDecisionRequest를 구성해 오케스트레이터에 전달해야 한다")
    void analyzeWithContextShouldUseStandardPipeline() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("The request matches the normal work pattern.");
        response.setRiskScore(0.22);
        response.setConfidence(0.83);

        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
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

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-pipeline-001")
                .timestamp(LocalDateTime.of(2026, 3, 24, 14, 0).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/customer/export");

        SecurityDecision decision = strategy.analyzeWithContext(event);

        ArgumentCaptor<SecurityDecisionRequest> requestCaptor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(requestCaptor.capture(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));

        // eventId가 request context에 그대로 전달되어야 후단 evidence, prompt audit, outbox linkage가 맞물린다.
        assertThat(requestCaptor.getValue().getContext().getSecurityEvent().getEventId()).isEqualTo("event-layer1-pipeline-001");
        // 파이프라인 응답은 ZeroTrustAction과 audit score로 정확히 변환되어야 한다.
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.getReasoning()).isEqualTo("The request matches the normal work pattern.");
        assertThat(decision.resolveAuditRiskScore()).isEqualTo(0.22);
        assertThat(decision.resolveAuditConfidence()).isEqualTo(0.83);
    }

    @Test
    @DisplayName("Layer1 pipeline should fail closed when LLM execution exceeds layer budget")
    void analyzeWithContext_pipelineTimeout_returnsEscalationFallback() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setLlmMs(10);

        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.never());

        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                null,
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

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-timeout-001")
                .timestamp(LocalDateTime.of(2026, 4, 22, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-timeout")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();

        SecurityDecision decision = strategy.analyzeWithContext(event);

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getProcessingLayer()).isEqualTo(1);
    }

    @Test
    @DisplayName("N-OUT-1 (G1-7): the Layer1 budget holds when the pipeline runs synchronously")
    void theLayerOneBudgetHoldsWhenThePipelineRunsSynchronously() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setLlmMs(200);

        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.fromCallable(() -> {
                    Thread.sleep(2000);
                    return new SecurityDecisionResponse();
                }));

        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                null,
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

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-timeout-001")
                .timestamp(LocalDateTime.of(2026, 4, 22, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-timeout")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();

        long started = System.currentTimeMillis();
        SecurityDecision decision = strategy.analyzeWithContext(event);
        long elapsedMs = System.currentTimeMillis() - started;

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getProcessingLayer()).isEqualTo(1);
        assertThat(elapsedMs).isLessThan(1500L);
    }

    @Test
    @DisplayName("N-OUT-1 (G1-7): the Layer1 total budget holds for the asynchronous analysis")
    void theLayerOneTotalBudgetHoldsForTheAsynchronousAnalysis() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setLlmMs(5000);
        properties.getLayer1().getTimeout().setTotalMs(200);

        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.fromCallable(() -> {
                    Thread.sleep(2000);
                    return new SecurityDecisionResponse();
                }));

        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                null,
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

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-timeout-001")
                .timestamp(LocalDateTime.of(2026, 4, 22, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-timeout")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();

        long started = System.currentTimeMillis();
        SecurityDecision decision = strategy.analyzeWithContextAsync(event).block();
        long elapsedMs = System.currentTimeMillis() - started;

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getProcessingLayer()).isEqualTo(1);
        assertThat(elapsedMs).isLessThan(1500L);
    }

    @Test
    @DisplayName("Layer1 response-action fallback audit fields must survive ThreatAssessment conversion")
    void evaluate_responseActionFallback_shouldPreserveAuditFields() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("CHALLENGE");
        response.setReasoning("Fresh verification is required.");
        response.withMetadata("llmDecisionPresent", false);
        response.withMetadata("rawExecutionSucceeded", true);
        response.withMetadata("securityDecisionParsingFallbackApplied", true);
        response.withMetadata("securityDecisionFallbackApplied", true);
        response.withMetadata("securityDecisionParseFailureCategory", "ACTION_FORMAT_INVALID");
        response.withMetadata("securityDecisionFallbackAction", "CHALLENGE");

        when(pipelineOrchestrator.execute(
                any(SecurityDecisionRequest.class),
                any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        TieredStrategyProperties properties = new TieredStrategyProperties();
        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                null,
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
                properties);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-response-fallback")
                .timestamp(LocalDateTime.of(2026, 7, 30, 4, 48).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-response-fallback")
                .sourceIp("203.0.113.10")
                .description("GET /api/protected")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/api/protected");

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment.getLlmDecisionPresent()).isFalse();
        assertThat(assessment.getTechnicalFallbackApplied()).isFalse();
        assertThat(assessment.getResponseActionFallbackApplied()).isTrue();
        assertThat(assessment.getResponseActionFallbackCategory()).isEqualTo("ACTION_FORMAT_INVALID");
        assertThat(assessment.getResponseActionFallbackAction()).isEqualTo("CHALLENGE");
    }

    /** W3-4: the past record search starts at the analysis entry, so the earlier stages' time counts towards it. */
    @Test
    @DisplayName("Layer1 starts the past record search at entry and waits for it where the records are first needed (W3-4)")
    void thePastRecordSearchRunsWhileTheEarlierStagesWork() {
        TieredStrategyProperties properties = interactiveWait(150);
        UnifiedVectorService vectorService = searchTaking(400, null);
        BaselineLearningService baselineLearningService = baselineTaking(700, null);
        SecurityEvent event = pastRecordEvent("event-w34-overlap");

        SecurityDecision decision = layer1(vectorService, baselineLearningService, properties).analyzeWithContext(event);

        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("relatedDocumentCount", 1);
        assertThat(millis(event, "layer1RagWaitMs")).isLessThan(150L);
        assertThat(millis(event, "layer1RagSearchMs")).isGreaterThanOrEqualTo(400L);
        assertThat(decision.getBehaviorPatterns()).isNotEmpty();
        // The search overlaps the earlier stages: only the time blocked on it is time spent before the model call.
        long total = millis(event, "layer1TotalMs");
        assertThat(((Number) decision.getSessionContext().get("preLlmPreparationMs")).longValue()).isLessThanOrEqualTo(total);
        long stages = 0L;
        for (String stage : List.of("layer1SessionContextMs", "layer1RagWaitMs", "layer1BehaviorAnalysisMs",
                "layer1PromptPreparationMs", "layer1PipelineBlockMs", "layer1ResponseValidateMs", "layer1PostProcessMs",
                "layer1PromptTelemetryCaptureMs", "layer1DecisionConvertMs", "layer1RuntimeTelemetryApplyMs",
                "layer1EscalateClassificationMs", "layer1ContextEnrichMs")) {
            stages += millis(event, stage);
        }
        assertThat(millis(event, "layer1UnaccountedMs")).isEqualTo(Math.max(0L, total - stages));
    }

    private static long millis(SecurityEvent event, String key) {
        return ((Number) event.getMetadata().get(key)).longValue();
    }

    /** W3-4: the interactive wait is counted from where the records are first needed, not from the search start. */
    @Test
    @DisplayName("Layer1 waits the interactive wait from where the past records are first needed (W3-4)")
    void theWaitIsCountedFromWhereTheRecordsAreNeeded() {
        TieredStrategyProperties properties = interactiveWait(300);
        UnifiedVectorService vectorService = searchTaking(400, null);
        BaselineLearningService baselineLearningService = baselineTaking(250, null);
        SecurityEvent event = pastRecordEvent("event-w34-wait");

        layer1(vectorService, baselineLearningService, properties).analyzeWithContext(event);

        assertThat(event.getMetadata()).containsEntry("ragRetrievalState", "AVAILABLE");
        assertThat(millis(event, "layer1RagWaitMs")).isPositive();
    }

    /** W3-4: the stage total counts the time blocked on the search; the search time that overlapped stays out of it. */
    @Test
    @DisplayName("Layer1 timing counts only the time blocked on the past record search towards the stage total (W3-4)")
    void theStageTotalCountsOnlyTheTimeBlockedOnTheSearch() {
        SecurityEvent event = pastRecordEvent("event-w34-total");

        layer1(null, null, new TieredStrategyProperties())
                .recordLayer1TimingMetadata(event, 0L, 400L, 0L, 700L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 710L);

        assertThat(millis(event, "layer1RagSearchMs")).isEqualTo(400L);
        assertThat(millis(event, "layer1RagWaitMs")).isZero();
        assertThat(millis(event, "layer1UnaccountedMs")).isEqualTo(10L);
    }

    @Test
    @DisplayName("Layer1 writes a past record search still running at the wait as not retrieved this time (W3-4)")
    void aSearchStillRunningAtTheWaitIsWrittenAsNotRetrievedThisTime() {
        TieredStrategyProperties properties = interactiveWait(150);
        UnifiedVectorService vectorService = searchTaking(900, null);
        BaselineLearningService baselineLearningService = baselineTaking(0, null);
        SecurityEvent event = pastRecordEvent("event-w34-timeout");

        layer1(vectorService, baselineLearningService, properties).analyzeWithContext(event);

        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "TIMEOUT")
                .containsEntry("relatedDocumentCount", 0);
    }

    private TieredStrategyProperties interactiveWait(long waitMs) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setInteractiveRagWaitMs(waitMs);
        properties.getLayer1().getTimeout().setRagMs(5000);
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("The request matches the normal work pattern.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));
        return properties;
    }

    private static UnifiedVectorService searchTaking(long millis, AtomicLong ended) {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        Document record = new Document("User accessed a previous public resource.", Map.of(
                "documentType", "behavior",
                "userId", "alice",
                "tenantId", "demo",
                "organizationId", "demo-org",
                "retrievalPurpose", "security_investigation",
                "accessScope", "USER"));
        when(vectorService.searchSimilar(any(SearchRequest.class))).thenAnswer(invocation -> {
            Thread.sleep(millis);
            if (ended != null) {
                ended.set(System.nanoTime());
            }
            return List.of(record);
        });
        return vectorService;
    }

    private static BaselineLearningService baselineTaking(long millis, AtomicLong started) {
        BaselineLearningService baselineLearningService = mock(BaselineLearningService.class);
        when(baselineLearningService.getPersonalBaseline(eq("alice"), any())).thenAnswer(invocation -> {
            if (started != null) {
                started.compareAndSet(0L, System.nanoTime());
            }
            Thread.sleep(millis);
            return null;
        });
        return baselineLearningService;
    }

    private Layer1ContextualStrategy layer1(UnifiedVectorService vectorService,
                                            BaselineLearningService baselineLearningService,
                                            TieredStrategyProperties properties) {
        return new Layer1ContextualStrategy(
                vectorService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                baselineLearningService,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                properties);
    }

    private static SecurityEvent pastRecordEvent(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(LocalDateTime.of(2026, 9, 30, 10, 0).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-" + eventId)
                .sourceIp("203.0.113.10")
                .description("GET /api/data")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/api/data");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("organizationId", "demo-org");
        return event;
    }
}
