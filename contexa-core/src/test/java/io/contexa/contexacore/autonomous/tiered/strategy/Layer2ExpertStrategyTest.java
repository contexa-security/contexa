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

import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import java.time.ZoneId;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Layer2ExpertStrategyTest {

    @Mock
    private ApprovalService approvalService;

    @Mock
    private PipelineOrchestrator pipelineOrchestrator;

    private Layer2ExpertStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                new TieredStrategyProperties(),
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
    }

    @Test
    @DisplayName("performDeepAnalysis should use standard pipeline and return valid SecurityDecision")
    void performDeepAnalysis_pipelineSuccess_returnsValidDecision() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.3);
        response.setConfidence(0.85);
        response.setAction("ALLOW");
        response.setReasoning("Legitimate access confirmed");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> requestCaptor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(requestCaptor.capture(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));

        assertThat(requestCaptor.getValue().getContext().getSecurityEvent().getEventId()).isEqualTo("test-event-layer2");
        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.resolveAuditRiskScore()).isEqualTo(0.3);
        assertThat(decision.resolveAuditConfidence()).isEqualTo(0.85);
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
    }

    /** N-OUT-1 (G1-8): the second layer runs on tier 2 and records the model that answered. */
    @Test
    void theSecondLayerRunsOnTierTwoAndRecordsTheModelThatAnswered() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("Legitimate access confirmed");
        response.withMetadata("providerResponseModel", "gpt-6-luna-2026-09-30");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> requestCaptor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(requestCaptor.capture(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));
        assertThat(requestCaptor.getValue().getParameter("platformAnalysisTier", Integer.class)).isEqualTo(2);
        assertThat(decision.getLlmModel()).isEqualTo("gpt-6-luna-2026-09-30");
    }

    /**
     * 판정층 8절 7: no analysis follows the second pass and no person reviews a request, so a second pass ESCALATE is
     * terminalized also where a v20 policy rule (P3) asks for one; the Q-87 exception is withdrawn.
     */
    @Test
    void anEscalateThePolicyRuleAsksForIsTerminalizedToo() {
        SecurityEvent event = buildTestEvent();
        event.addMetadata("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("CRITICAL").actionFamily("EXPORT").build())
                .decisionFacts(new DecisionFacts(List.of(), List.of(),
                        new PolicySatisfaction(false, null, List.of(), "no approval", List.of()), List.of()))
                .build());
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ESCALATE");
        response.setReasoning("No approval covers the export.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getAutonomyConstraintReasons()).contains("LAYER2_ESCALATE_TERMINALIZED");
    }

    /** Under a rule whose floor is a challenge (P1) the ESCALATE is terminalized as before. */
    @Test
    void anEscalateUnderAChallengeFloorIsStillTerminalized() {
        SecurityEvent event = buildTestEvent();
        event.addMetadata("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("CRITICAL").actionFamily("READ").build())
                .decisionFacts(new DecisionFacts(List.of(), List.of(
                        new Deviation(DeviationDimension.TIME, "x", true, true, 0, 10, "y",
                                Deviation.Explanation.UNEXPLAINED, null),
                        new Deviation(DeviationDimension.NETWORK, "x", true, true, 0, 10, "y",
                                Deviation.Explanation.UNEXPLAINED, null)),
                        PolicySatisfaction.UNKNOWN, List.of()))
                .build());
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ESCALATE");
        response.setReasoning("Two identity signals differ from the baseline.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    /**
     * PR-83: a failed model call leaves no ESCALATE: no analysis follows this one and no person reviews a request, so
     * it ends by the same terminal policy as a second pass ESCALATE, and the record shows a technical fallback.
     */
    @Test
    @DisplayName("performDeepAnalysis should end as the escalate fallback action when the LLM pipeline fails")
    void performDeepAnalysis_pipelineFailure_endsAsTheEscalateFallbackAction() {
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getLlmDecisionPresent()).isFalse();
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getTechnicalFallbackAction()).isEqualTo("CHALLENGE");
        assertThat(decision.getResponseActionFallbackApplied()).isNull();
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
        assertThat(decision.getAutonomyConstraintApplied()).isTrue();
        assertThat(decision.getAutonomyConstraintReasons()).containsExactly("LAYER2_ESCALATE_TERMINALIZED");
        assertThat(decision.getAutonomyConstraintPolicy()).isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY);
        assertThat(decision.getAutonomyConstraintSummary()).startsWith("Layer2 analysis failed");
        assertThat(decision.getReasoning()).contains("Layer 2 LLM call failed").doesNotContain("manual review");
        assertThat(decision.isRequiresApproval()).isFalse();
        assertThat(decision.getFieldProvenance()).containsOnly(
                Map.entry("riskScore", "PLATFORM_FALLBACK"),
                Map.entry("confidence", "PLATFORM_FALLBACK"),
                Map.entry("reasoning", "PLATFORM_FALLBACK"),
                Map.entry("mitre", "PLATFORM_FALLBACK"),
                Map.entry("evidenceRefs", "PLATFORM_FALLBACK"));
    }

    /** allow-escalate-final-action keeps what it has always done: a failed call ends as ESCALATE, held for review. */
    @Test
    void anAllowedFinalEscalateStaysWhenTheLlmPipelineFails() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);
        strategy = strategyWith(properties);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getTechnicalFallbackAction()).isEqualTo("ESCALATE");
        assertThat(decision.getAutonomyConstraintApplied()).isNotEqualTo(Boolean.TRUE);
        assertThat(decision.getReasoning()).contains("escalating for manual review");
        assertThat(decision.isRequiresApproval()).isTrue();
    }

    /** The setting's own value ends a failure as it ends a second pass ESCALATE; one that ends nothing is CHALLENGE. */
    @ParameterizedTest
    @CsvSource({"BLOCK,BLOCK", "ALLOW,ALLOW", "CHALLENGE,CHALLENGE", "ESCALATE,CHALLENGE",
            "PENDING_ANALYSIS,CHALLENGE"})
    void aFailedCallEndsAsTheConfiguredFallback(ZeroTrustAction configured, ZeroTrustAction expected) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setEscalateFallbackAction(configured);
        strategy = strategyWith(properties);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAutonomousAction()).isEqualTo(expected);
        assertThat(decision.getTechnicalFallbackAction()).isEqualTo(expected.name());
    }

    @Test
    void aFailedCallEndsAsChallengeWithoutAConfiguredFallback() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setEscalateFallbackAction(null);
        strategy = strategyWith(properties);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        assertThat(strategy.performDeepAnalysis(buildTestEvent()).getAutonomousAction())
                .isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    /** The cold path reads the assessment: the proposal stays ESCALATE, what is enforced is the fallback. */
    @Test
    void theAssessmentOfAFailedCallCarriesTheFallbackAsItsEnforcedAction() {
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        ThreatAssessment assessment = strategy.evaluate(buildTestEvent());

        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
        assertThat(assessment.getAutonomousAction()).isEqualTo("CHALLENGE");
        assertThat(assessment.getRecommendedActions()).containsExactly("REQUIRE_REAUTHENTICATION");
        assertThat(assessment.getTechnicalFallbackApplied()).isTrue();
        assertThat(assessment.getLlmDecisionPresent()).isFalse();
    }

    @Test
    void theAsyncAnalysisEndsAFailureTheSameWay() {
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysisAsync(buildTestEvent()).block();

        assertThat(decision).isNotNull();
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    /** The async wrapper's own budget ends the wait: its fallback is the same decision. */
    @Test
    void theAsyncBudgetEndsAFailureTheSameWay() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setTimeoutMs(50);
        strategy = strategyWith(properties);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenAnswer(invocation -> {
                    Thread.sleep(500);
                    return Mono.never();
                });

        SecurityDecision decision = strategy.performDeepAnalysisAsync(buildTestEvent()).block();

        assertThat(decision).isNotNull();
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
    }

    /**
     * PR-83: a restriction is never lowered. A model's own CHALLENGE or BLOCK stands when a step after it fails: the
     * failure is the platform's, the decision the model's, and a BLOCK must not become the fallback's CHALLENGE.
     */
    @ParameterizedTest
    @ValueSource(strings = {"BLOCK", "CHALLENGE"})
    void aModelsRestrictionStandsWhenAStepAfterItFails(String modelAction) {
        strategy = strategyFailingAfterTheModel(new TieredStrategyProperties());
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction(modelAction);
        response.setReasoning("The export is outside the owner's work.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.valueOf(modelAction));
        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.valueOf(modelAction));
        assertThat(decision.getLlmDecisionPresent()).isTrue();
        assertThat(decision.getTechnicalFallbackApplied()).isFalse();
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
    }

    /** A model's ALLOW is no restriction to keep: the failed step ends it as a failure, which is the stricter end. */
    @Test
    void aModelsAllowEndsAsTheFallbackWhenAStepAfterItFails() {
        strategy = strategyFailingAfterTheModel(new TieredStrategyProperties());
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("Routine work.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
    }

    /** With the final ESCALATE allowed a failed step ends as before. */
    @Test
    void anAllowedFinalEscalateStaysWhenAStepAfterTheModelFails() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);
        strategy = strategyFailingAfterTheModel(properties);
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("BLOCK");
        response.setReasoning("The export is outside the owner's work.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    /** The real analysis with a learning step that fails, the last step after the model answered. */
    private Layer2ExpertStrategy strategyFailingAfterTheModel(TieredStrategyProperties properties) {
        SecurityLearningService learning = mock(SecurityLearningService.class);
        doThrow(new IllegalStateException("learning store down")).when(learning)
                .postProcessDecision(any(SecurityEvent.class), any(SecurityDecision.class));
        return new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                properties,
                learning,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
    }

    @Test
    @DisplayName("the expert strategy reads the ids a session had from the context store (P2 correction 5)")
    void previousSessionIds_comeFromTheContextStore() {
        InMemorySecurityContextDataStore dataStore = new InMemorySecurityContextDataStore();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        Layer2ExpertStrategy sessionStrategy = new Layer2ExpertStrategy(
                approvalService,
                dataStore,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                properties,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );

        dataStore.moveSessionRecords("session-old", "session-new");

        assertThat(sessionStrategy.previousSessionIds("session-new")).containsExactly("session-old");
    }

    @Test
    @DisplayName("performDeepAnalysis should end as the escalate fallback action when the pipeline exceeds the layer budget")
    void performDeepAnalysis_pipelineTimeout_endsAsTheEscalateFallbackAction() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setTimeoutMs(10);
        strategy = new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                properties,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.never());

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getResponseActionFallbackApplied()).isNull();
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
        assertThat(decision.getFieldProvenance().values())
                .containsOnly("PLATFORM_FALLBACK");
    }

    /** allow-escalate-final-action keeps what it has always done: a call past the budget ends as ESCALATE. */
    @Test
    void anAllowedFinalEscalateStaysWhenThePipelineExceedsTheLayerBudget() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);
        properties.getLayer2().setTimeoutMs(10);
        strategy = strategyWith(properties);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.never());

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
    }

    @Test
    @DisplayName("N-OUT-1 (G1-7): the Layer2 budget holds when the pipeline runs synchronously")
    void theLayerTwoBudgetHoldsWhenThePipelineRunsSynchronously() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setTimeoutMs(200);
        strategy = new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                properties,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.fromCallable(() -> {
                    Thread.sleep(2000);
                    return new SecurityDecisionResponse();
                }));

        long started = System.currentTimeMillis();
        SecurityDecision decision = strategy.performDeepAnalysis(event);
        long elapsedMs = System.currentTimeMillis() - started;

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getResponseActionFallbackApplied()).isNull();
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
        assertThat(elapsedMs).isLessThan(1500L);
        assertThat(decision.getFieldProvenance().values())
                .containsOnly("PLATFORM_FALLBACK");
    }

    @Test
    @DisplayName("missing Layer2 response action should apply CHALLENGE without technical fallback")
    void performDeepAnalysis_missingAction_appliesResponseFallbackChallenge() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.4);
        response.setConfidence(0.7);
        response.setReasoning("Evidence was evaluated but action was omitted");
        when(pipelineOrchestrator.execute(
                any(SecurityDecisionRequest.class),
                any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isFalse();
        assertThat(decision.getLlmDecisionPresent()).isFalse();
        assertThat(decision.getResponseActionFallbackApplied()).isTrue();
        assertThat(decision.getResponseActionFallbackCategory()).isEqualTo("ACTION_MISSING");
        assertThat(decision.getResponseActionFallbackAction()).isEqualTo("CHALLENGE");
    }

    @Test
    @DisplayName("invalid Layer2 response action should apply CHALLENGE without technical fallback")
    void performDeepAnalysis_invalidAction_appliesResponseFallbackChallenge() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.4);
        response.setConfidence(0.7);
        response.setAction("RETRY_LATER");
        response.setReasoning("Unsupported action format");
        when(pipelineOrchestrator.execute(
                any(SecurityDecisionRequest.class),
                any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isFalse();
        assertThat(decision.getLlmDecisionPresent()).isFalse();
        assertThat(decision.getResponseActionFallbackApplied()).isTrue();
        assertThat(decision.getResponseActionFallbackCategory()).isEqualTo("ACTION_FORMAT_INVALID");
        assertThat(decision.getResponseActionFallbackAction()).isEqualTo("CHALLENGE");
    }

    @Test
    @DisplayName("resolveOrganizationId should not use tenant metadata as organization identity")
    void resolveOrganizationId_shouldNotUseTenantMetadata() {
        SecurityEvent event = buildTestEvent();
        event.addMetadata("tenantId", "tenant-a");

        assertThat(strategy.resolveOrganizationId(event)).isEqualTo("unresolved:event:test-event-layer2");
    }

    @Test
    @DisplayName("resolveOrganizationId should isolate unresolved events instead of returning shared default")
    void resolveOrganizationId_missingTenant_shouldUseEventScopedFallback() {
        SecurityEvent event = buildTestEvent();

        assertThat(strategy.resolveOrganizationId(event)).isEqualTo("unresolved:event:test-event-layer2");
    }

    @Test
    @DisplayName("performDeepAnalysis should return failsafe BLOCK for null event")
    void performDeepAnalysis_nullEvent_returnsFailsafeBlock() {
        SecurityDecision decision = strategy.performDeepAnalysis(null);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("getLayerName should return Layer2")
    void getLayerName_returnsLayer2() {
        assertThat(strategy.getStrategyName()).isEqualTo("Layer2-Expert-Strategy");
    }

    /** W4-3: the reason codes of the model response reach the expert assessment. */
    @Test
    void evaluate_keepsTheReasonCodesOfTheResponse() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("CHALLENGE");
        response.setReasoning("The export time differs from usual.");
        response.setReasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1")));
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment.getReasonCodes()).containsExactly(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1"));
    }

    @Test
    @DisplayName("evaluate should return ThreatAssessment with shouldEscalate=false")
    void evaluate_returnsAssessmentWithShouldEscalateFalse() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.4);
        response.setConfidence(0.8);
        response.setAction("CHALLENGE");
        response.setReasoning("Verify user");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isFalse();
        assertThat(assessment.getStrategyName()).isEqualTo("Layer2-Expert");
        assertThat(assessment.getAction()).isEqualTo("CHALLENGE");
    }

    @Test
    @DisplayName("Layer2 terminal fallback preserves the LLM ESCALATE proposal and exposes the final action")
    void performDeepAnalysis_escalateProposal_preservesProposalAndFinalFallback() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        strategy = new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                properties,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.7);
        response.setConfidence(0.8);
        response.setAction("ESCALATE");
        response.setReasoning("Expert review is required");
        when(pipelineOrchestrator.execute(
                any(SecurityDecisionRequest.class),
                any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getAutonomyConstraintApplied()).isTrue();
        assertThat(decision.getAutonomyConstraintReasons())
                .containsExactly("LAYER2_ESCALATE_TERMINALIZED");
        assertThat(decision.getAutonomyConstraintPolicy())
                .isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY);
        assertThat(decision.getAutonomyConstraintSource())
                .isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY_SOURCE);
        assertThat(decision.getAutonomyConstraintVersion())
                .isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY_VERSION);

        ThreatAssessment assessment = strategy.evaluate(buildTestEvent());

        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
        assertThat(assessment.getAutonomousAction()).isEqualTo("CHALLENGE");
        assertThat(assessment.getAutonomyConstraintPolicy())
                .isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY);
        assertThat(assessment.getAutonomyConstraintSource())
                .isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY_SOURCE);
        assertThat(assessment.getAutonomyConstraintVersion())
                .isEqualTo(Layer2ExpertStrategy.ESCALATE_TERMINAL_POLICY_VERSION);
    }

    /**
     * R4-L2: no event metadata forces a BLOCK. A signal that names the former probe source is the event's own text, so
     * the ESCALATE proposal ends as the terminal policy says, without a confirmed-malicious constraint or explanation.
     */
    @Test
    void aSignalNamingTheFormerProbeSourceForcesNoBlock() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.9);
        response.setConfidence(0.8);
        response.setAction("ESCALATE");
        response.setReasoning("Expert review is required");
        when(pipelineOrchestrator.execute(
                any(SecurityDecisionRequest.class),
                any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));
        SecurityEvent event = buildTestEvent();
        event.addMetadata("anomalySignal", "CONFIRMED_CREDENTIAL_EXFILTRATION");
        event.addMetadata("anomalySignalSource", "OFFICIAL_VERIFICATION_INTERNAL");

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getAutonomyConstraintReasons()).doesNotContain("CONFIRMED_MALICIOUS_ACTIVITY");
        assertThat(decision.getAutonomyConstraintPolicy()).isNotEqualTo("TRUSTED_CONFIRMED_MALICIOUS_SIGNAL");
        assertThat(decision.getReasoning()).doesNotContain("trusted internal security signal");
    }

    /**
     * 판정층 E-4 (replaces W3-9's skip): a first pass that handed the request over is decided by the second pass's own
     * model, also when its past record search found nothing new; the first verdict never becomes the final one.
     */
    @Test
    void aFirstPassWithNothingNewIsStillDecidedByTheSecondPassModel() {
        Layer2ExpertStrategy secondPass = strategyWith(new TieredStrategyProperties());
        SecurityEvent event = firstPassEscalated("w39-nothing-new", "ZERO_RESULTS", false, V20_LAYOUT);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(allow()));

        SecurityDecision decision = secondPass.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> captor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(captor.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(captor.getValue().getParameters())
                .containsEntry("layer2FirstPassVerdict", "ESCALATE")
                .containsEntry("layer2FirstPassPastRecordsState", "ZERO_RESULTS");
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
        assertThat(event.getMetadata()).doesNotContainKey("layer2ModelCallSkipped");
    }

    /** 판정층 E-5: a v21 second pass that still answers ESCALATE is terminalized like every other bundle's. */
    @Test
    void aV21SecondPassEscalateIsTerminalized() {
        TieredStrategyProperties v21 = new TieredStrategyProperties();
        v21.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        Layer2ExpertStrategy secondPass = strategyWith(v21);
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ESCALATE");
        response.setReasoning("The facts conflict.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(response));

        SecurityDecision decision = secondPass.performDeepAnalysis(buildTestEvent());

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getAutonomyConstraintReasons()).contains("LAYER2_ESCALATE_TERMINALIZED");
    }

    /**
     * 판정층 E-5: v21 has no rule floor (V-5), so a v21 second pass ESCALATE is terminalized also where a v20 minimum
     * action rule would ask for a review.
     */
    @Test
    void aV21SecondPassEscalateIsTerminalizedAlsoWhereAV20RuleWouldAskForAReview() {
        TieredStrategyProperties v21 = new TieredStrategyProperties();
        v21.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        Layer2ExpertStrategy secondPass = strategyWith(v21);
        SecurityEvent event = buildTestEvent();
        event.addMetadata("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("CRITICAL").actionFamily("EXPORT").build())
                .decisionFacts(new DecisionFacts(List.of(), List.of(),
                        new PolicySatisfaction(false, null, List.of(), "no approval", List.of()), List.of()))
                .build());
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ESCALATE");
        response.setReasoning("No approval covers the export.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(response));

        SecurityDecision decision = secondPass.performDeepAnalysis(event);

        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getAutonomyConstraintReasons()).contains("LAYER2_ESCALATE_TERMINALIZED");
    }

    /** W3-9: past records the first pass could not retrieve and this pass found are the only facts added. */
    @Test
    void aFirstPassThatCouldNotRetrievePastRecordsGetsOnlyTheFoundOnesAdded() {
        Layer2ExpertStrategy secondPass = strategyWith(new TieredStrategyProperties());
        String eventId = "w39-new-records";
        List<Document> found = List.of(new Document("past record one", Map.of("id", "past-1")));
        AbstractTieredStrategy.cacheEscalationContext(eventId, null, null, found);
        SecurityEvent event = firstPassEscalated(eventId, "TIMEOUT", false, V20_LAYOUT);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(allow()));

        SecurityDecision decision = secondPass.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> captor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(captor.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(captor.getValue().getParameters())
                .containsEntry("layer2FirstPassUserPrompt", FIRST_PROMPT)
                .containsEntry("layer2FirstPassVerdict", "ESCALATE")
                .containsEntry("layer2FirstPassPastRecordsState", "TIMEOUT");
        assertThat(captor.getValue().getContext().getRelatedDocuments()).containsExactlyElementsOf(found);
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(event.getMetadata()).doesNotContainKey("layer2ModelCallSkipped");
    }

    /**
     * N-MISS-1 (D8): when Layer2's own search finds the records the first pass's search timed out on, the event records
     * this search's state with the earlier timeout apart, and the second pass still gets the first pass's state.
     */
    @Test
    void aSearchAfterTheFirstPassTimedOutRecordsItsOwnStateAndTheSecondPassKeepsTheFirst() {
        UnifiedVectorService vectorService = mock(UnifiedVectorService.class);
        Document record = new Document("User exported project GB-500.", Map.of(
                "documentType", "behavior",
                "userId", "user-002",
                "tenantId", "demo",
                "organizationId", "demo-org",
                "retrievalPurpose", "security_investigation",
                "accessScope", "USER",
                "eventId", "past-event-1"));
        when(vectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of(record));
        TieredStrategyProperties properties = new TieredStrategyProperties();
        Layer2ExpertStrategy secondPass = new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                vectorService,
                null,
                null,
                properties,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
        SecurityEvent event = firstPassEscalated("n-miss-1-d8", "TIMEOUT", false, V20_LAYOUT);
        event.getMetadata().put("ragTimedOut", true);
        event.getMetadata().put("tenantId", "demo");
        event.getMetadata().put("organizationId", "demo-org");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(allow()));

        secondPass.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> captor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(captor.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(captor.getValue().getParameters()).containsEntry("layer2FirstPassPastRecordsState", "TIMEOUT");
        assertThat(captor.getValue().getContext().getRelatedDocuments()).hasSize(1);
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("ragTimedOut", false)
                .containsEntry("ragEarlierRetrievalState", "TIMEOUT")
                .containsEntry("relatedDocumentCount", 1);
    }

    /** W3-9: without a model verdict (a technical fallback) Layer2 makes the first model decision, as before. */
    @Test
    void aFirstPassWithoutAModelVerdictIsAnalysedAsBefore() {
        Layer2ExpertStrategy secondPass = strategyWith(new TieredStrategyProperties());
        SecurityEvent event = firstPassEscalated("w39-technical", "ZERO_RESULTS", true, V20_LAYOUT);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(allow()));

        secondPass.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> captor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(captor.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(captor.getValue().getParameters()).doesNotContainKeys(
                "layer2FirstPassUserPrompt", "layer2FirstPassVerdict", "layer2FirstPassPastRecordsState");
        assertThat(event.getMetadata()).doesNotContainKey("layer2ModelCallSkipped");
    }

    /** W3-9: the v19 sections stay the comparison baseline, so Layer2 is asked as before. */
    @Test
    void theV19FormatAsksLayer2AsBefore() {
        Layer2ExpertStrategy secondPass = strategyWith(new TieredStrategyProperties());
        SecurityEvent event = firstPassEscalated("w39-v19", "ZERO_RESULTS", false, null);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(allow()));

        secondPass.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> captor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(captor.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(captor.getValue().getParameters()).doesNotContainKeys(
                "layer2FirstPassUserPrompt", "layer2FirstPassVerdict", "layer2FirstPassPastRecordsState");
        assertThat(event.getMetadata()).doesNotContainKey("layer2ModelCallSkipped");
    }

    /**
     * W3-16: one event runs one bundle, so the first prompt's layout decides the second pass; no setting of this layer
     * does (the user prompt format setting is gone). A v20 first prompt is drawn again for the second pass, which asks
     * its model (판정층 E-4: also with nothing new).
     */
    @Test
    void theFirstPromptsBundleDecidesTheSecondPassWithoutAnySetting() {
        Layer2ExpertStrategy secondPass = strategyWith(new TieredStrategyProperties());
        SecurityEvent event = firstPassEscalated("w316-v20-first", "ZERO_RESULTS", false, V20_LAYOUT);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(allow()));

        secondPass.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> captor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(captor.capture(), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(captor.getValue().getParameters()).containsKeys(
                "layer2FirstPassUserPrompt", "layer2FirstPassVerdict", "layer2FirstPassPastRecordsState");
        assertThat(event.getMetadata()).doesNotContainKey("layer2ModelCallSkipped");
    }

    /**
     * 판정층 E-4 (replaces N-RSN-1's kept first verdict): the first pass's model values reach the second pass on the
     * cold path's hand-over, and the decision is the second pass model's with its own values; the first pass's
     * ESCALATE, risk score, confidence and reason codes do not become the final ones.
     */
    @Test
    void theSecondPassDecisionCarriesItsOwnValuesNotTheFirstPasss() {
        Layer2ExpertStrategy secondPass = strategyWith(new TieredStrategyProperties());
        SecurityEvent event = firstPassEscalatedWithModelValues("n-rsn-1-values");
        SecurityDecisionResponse answer = allow();
        answer.setRiskScore(0.31);
        answer.setConfidence(0.84);
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(answer));

        ThreatAssessment assessment = secondPass.evaluate(event);

        verify(pipelineOrchestrator).execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class));
        assertThat(assessment.getAction()).isEqualTo(ZeroTrustAction.ALLOW.name());
        assertThat(assessment.resolveAuditRiskScore()).isEqualTo(0.31);
        assertThat(assessment.resolveAuditConfidence()).isEqualTo(0.84);
        // The second pass answered without reason codes, so the decision has none of the first pass's.
        assertThat(assessment.getReasonCodes()).isNullOrEmpty();
    }

    private static final List<SecurityDecisionOutputContract.Citation> FIRST_PASS_REASON_CODES = List.of(
            new SecurityDecisionOutputContract.Citation("MIN_P3_POLICY_NOT_SATISFIED", "F4"),
            new SecurityDecisionOutputContract.Citation("DEVIATION_SIZE", "F1"));
    private static final Map<String, String> FIRST_PASS_PROVENANCE = Map.of("reasoning", "MODEL",
            "riskScore", "MODEL", "confidence", "MODEL", "reasonCodes", "MODEL");

    /**
     * N-RSN-1: the first pass as the cold path hands it over, with its model values in the assessment and its reason
     * codes under their own key (the key written as text, so this test compiles before the impl).
     */
    private static SecurityEvent firstPassEscalatedWithModelValues(String eventId) {
        SecurityEvent event = firstPassEscalated(eventId, "AVAILABLE", false, V20_LAYOUT);
        Map<String, Object> firstPass = new HashMap<>();
        firstPass.put("layer", "LAYER1");
        firstPass.put("llmAction", "ESCALATE");
        firstPass.put("autonomousAction", "ESCALATE");
        firstPass.put("llmDecisionPresent", true);
        firstPass.put("technicalFallbackApplied", false);
        firstPass.put("reasoning", "Business intent remains uncertain.");
        firstPass.put("riskScore", 0.78);
        firstPass.put("llmAuditConfidence", 0.97);
        firstPass.put("fieldProvenance", FIRST_PASS_PROVENANCE);
        event.getMetadata().put("layer1Assessment", Map.copyOf(firstPass));
        event.getMetadata().put("firstPassReasonCodes", FIRST_PASS_REASON_CODES);
        return event;
    }

    private static final String V20_LAYOUT = "v20-dictionary-blocks";
    private static final String FIRST_PROMPT = "=== USER BASELINE ===\nEvidence: state NONE\nBaselineStatus: NONE (new account)\n"
            + "\n=== REQUEST ===\nTime: Wed 03:17\n";

    private Layer2ExpertStrategy strategyWith(TieredStrategyProperties properties) {
        return new Layer2ExpertStrategy(
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                properties,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
    }

    private static SecurityDecisionResponse allow() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("The past records show the same work.");
        return response;
    }

    /** The event as the cold path hands it to Layer2: the Layer1 assessment and what the first pass left. */
    private static SecurityEvent firstPassEscalated(String eventId, String pastRecordsState, boolean technicalFallback,
                                                    String layout) {
        Map<String, Object> firstPass = new HashMap<>();
        firstPass.put("layer", "LAYER1");
        firstPass.put("llmAction", "ESCALATE");
        firstPass.put("autonomousAction", "ESCALATE");
        firstPass.put("llmDecisionPresent", !technicalFallback);
        firstPass.put("technicalFallbackApplied", technicalFallback);
        firstPass.put("reasoning", "Business intent remains uncertain.");
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "POST");
        metadata.put("requestPath", "/api/admin/config");
        metadata.put("layer1Assessment", Map.copyOf(firstPass));
        metadata.put(PromptRuntimeTelemetrySupport.FIRST_PASS_USER_PROMPT, FIRST_PROMPT);
        if (layout != null) {
            metadata.put("userPromptLayoutVersion", layout);
        }
        metadata.put("ragRetrievalState", pastRecordsState);
        return SecurityEvent.builder()
                .eventId(eventId)
                .userId("user-002")
                .sessionId("session-002")
                .sourceIp("10.0.0.50")
                .userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .metadata(metadata)
                .build();
    }

    private SecurityEvent buildTestEvent() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "POST");
        metadata.put("requestPath", "/api/admin/config");

        return SecurityEvent.builder()
                .eventId("test-event-layer2")
                .userId("user-002")
                .sessionId("session-002")
                .sourceIp("10.0.0.50")
                .userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
                .timestamp(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant())
                .metadata(metadata)
                .build();
    }
}
