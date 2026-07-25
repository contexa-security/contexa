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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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

    @Test
    @DisplayName("performDeepAnalysis should return technical ESCALATE when the LLM pipeline fails")
    void performDeepAnalysis_pipelineFailure_returnsTechnicalEscalate() {
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getResponseActionFallbackApplied()).isNull();
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
        assertThat(decision.getReasoning()).contains("escalating for manual review");
        assertThat(decision.getFieldProvenance()).containsOnly(
                Map.entry("riskScore", "PLATFORM_FALLBACK"),
                Map.entry("confidence", "PLATFORM_FALLBACK"),
                Map.entry("reasoning", "PLATFORM_FALLBACK"),
                Map.entry("mitre", "PLATFORM_FALLBACK"),
                Map.entry("evidenceRefs", "PLATFORM_FALLBACK"));
    }

    @Test
    @DisplayName("performDeepAnalysis should return technical ESCALATE when the pipeline exceeds the layer budget")
    void performDeepAnalysis_pipelineTimeout_returnsTechnicalEscalate() {
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
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getResponseActionFallbackApplied()).isNull();
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
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
                .timestamp(LocalDateTime.now())
                .metadata(metadata)
                .build();
    }
}
