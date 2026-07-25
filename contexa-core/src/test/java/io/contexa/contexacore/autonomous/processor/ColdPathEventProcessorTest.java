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
package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ColdPathEventProcessorTest {

    @Mock
    private Layer1ContextualStrategy contextualStrategy;

    @Mock
    private Layer2ExpertStrategy expertStrategy;

    @Mock
    private LlmAnalysisEventListener llmAnalysisEventListener;

    private ColdPathEventProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new ColdPathEventProcessor(contextualStrategy, expertStrategy, llmAnalysisEventListener);
    }

    @Test
    @DisplayName("Layer1 ALLOW decision should not invoke Layer2")
    void layer1AllowDecision_shouldNotInvokeLayer2() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-1")
                .sourceIp("10.0.0.1")
                .build();
        event.addMetadata("requestPath", "/api/test");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.1)
                .confidence(0.95)
                .action(ZeroTrustAction.ALLOW.name())
                .reasoning("Normal traffic")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);

        // when
        ProcessingResult result = processor.processEvent(event, 0.2);

        // then
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getProcessingPath()).isEqualTo(ProcessingResult.ProcessingPath.COLD_PATH);
        verify(expertStrategy, never()).evaluate(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("Layer1 ESCALATE should invoke Layer2")
    void layer1Escalate_shouldInvokeLayer2() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-2")
                .sourceIp("10.0.0.2")
                .build();
        event.addMetadata("requestPath", "/api/admin");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.4)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("Low confidence, escalating")
                .shouldEscalate(true)
                .build();

        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .riskScore(0.8)
                .confidence(0.9)
                .action(ZeroTrustAction.BLOCK.name())
                .reasoning("Confirmed threat")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);

        // when
        ProcessingResult result = processor.processEvent(event, 0.5);

        // then
        assertThat(result.isSuccess()).isTrue();
        verify(expertStrategy).evaluate(any(SecurityEvent.class));
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.BLOCK.name());
        assertThat(result.getProposedAction()).isEqualTo(ZeroTrustAction.BLOCK.name());
    }

    @Test
    @DisplayName("Layer2 terminal fallback should keep the proposal and expose policy metadata")
    void layer2TerminalFallback_shouldPreserveProposalAndPolicyMetadata() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-layer2-terminal")
                .sourceIp("10.0.0.22")
                .build();
        event.addMetadata("requestPath", "/api/sensitive");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("Layer2 analysis required")
                .shouldEscalate(true)
                .build();
        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .action(ZeroTrustAction.ESCALATE.name())
                .autonomousAction(ZeroTrustAction.CHALLENGE.name())
                .llmAuditRiskScore(0.7)
                .llmAuditConfidence(0.8)
                .reasoning("Human verification is required")
                .autonomyConstraintApplied(true)
                .autonomyConstraintReasons(List.of("LAYER2_ESCALATE_TERMINALIZED"))
                .autonomyConstraintSummary("Layer2 ESCALATE was terminalized to CHALLENGE.")
                .autonomyConstraintPolicy("LAYER2_ESCALATE_TERMINAL_POLICY")
                .autonomyConstraintSource("contexa.ai.tiered.layer2.escalate-fallback-action")
                .autonomyConstraintVersion("1")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);

        ProcessingResult result = processor.processEvent(event, 0.5);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getProposedAction()).isEqualTo(ZeroTrustAction.ESCALATE.name());
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name());
        assertThat(result.getAutonomyConstraintPolicy())
                .isEqualTo("LAYER2_ESCALATE_TERMINAL_POLICY");
        assertThat(result.getAutonomyConstraintSource())
                .isEqualTo("contexa.ai.tiered.layer2.escalate-fallback-action");
        assertThat(result.getAutonomyConstraintVersion()).isEqualTo("1");
        assertThat(result.getAnalysisData())
                .containsEntry("llmProposedAction", ZeroTrustAction.ESCALATE.name())
                .containsEntry("autonomousEnforcementAction", ZeroTrustAction.CHALLENGE.name())
                .containsEntry("autonomyConstraintPolicy", "LAYER2_ESCALATE_TERMINAL_POLICY")
                .containsEntry("autonomyConstraintVersion", "1");
        verify(llmAnalysisEventListener).onLayer2Complete(
                eq("user-layer2-terminal"),
                eq(ZeroTrustAction.CHALLENGE.name()),
                any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Layer2 response action fallback should remain distinct from technical fallback")
    void layer2ResponseActionFallback_shouldRemainDistinctFromTechnicalFallback() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-layer2-missing-action")
                .sourceIp("10.0.0.23")
                .build();
        event.addMetadata("requestPath", "/api/sensitive");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .action(ZeroTrustAction.ESCALATE.name())
                .shouldEscalate(true)
                .build();
        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .action(ZeroTrustAction.CHALLENGE.name())
                .autonomousAction(ZeroTrustAction.CHALLENGE.name())
                .technicalFallbackApplied(false)
                .responseActionFallbackApplied(true)
                .responseActionFallbackCategory("ACTION_MISSING")
                .responseActionFallbackReason("Layer2 LLM response action was missing; CHALLENGE was applied.")
                .responseActionFallbackAction(ZeroTrustAction.CHALLENGE.name())
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);

        ProcessingResult result = processor.processEvent(event, 0.5);

        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name());
        assertThat(result.getTechnicalFallbackApplied()).isFalse();
        assertThat(result.getResponseActionFallbackApplied()).isTrue();
        assertThat(result.getResponseActionFallbackCategory()).isEqualTo("ACTION_MISSING");
        assertThat(result.getResponseActionFallbackAction()).isEqualTo("CHALLENGE");
        assertThat(result.getAnalysisData())
                .containsEntry("responseActionFallbackApplied", true)
                .containsEntry("responseActionFallbackCategory", "ACTION_MISSING");
    }

    @Test
    @DisplayName("Layer2 failure should use fallback result")
    void layer2Failure_shouldUseFallback() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-3")
                .sourceIp("10.0.0.3")
                .build();
        event.addMetadata("requestPath", "/api/resource");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.3)
                .shouldEscalate(true)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class)))
                .thenThrow(new RuntimeException("Layer2 service unavailable"));

        // when
        ProcessingResult result = processor.processEvent(event, 0.5);

        // then
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name());
        assertThat(result.getConfidence()).isEqualTo(0.3);
    }

    @Test
    @DisplayName("Layer1 autonomy constraint should preserve LLM proposed action")
    void layer1AutonomyConstraint_shouldPreserveProposedAction() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-4")
                .sourceIp("10.0.0.5")
                .build();
        event.addMetadata("requestPath", "/api/export");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.2)
                .confidence(0.54)
                .llmAuditConfidence(0.91)
                .action(ZeroTrustAction.ALLOW.name())
                .autonomousAction(ZeroTrustAction.CHALLENGE.name())
                .reasoning("Semantically legitimate, but approval lineage is unresolved.")
                .autonomyConstraintApplied(true)
                .autonomyConstraintSummary("Autonomous allow is not permitted until approval lineage is explicit.")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);

        ProcessingResult result = processor.processEvent(event, 0.2);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getProposedAction()).isEqualTo(ZeroTrustAction.ALLOW.name());
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name());
        assertThat(result.getConfidence()).isEqualTo(0.54);
        assertThat(result.resolveAuditConfidence()).isEqualTo(0.91);
        assertThat(result.getAutonomyConstraintApplied()).isTrue();
    }

    @Test
    @DisplayName("official verification runs should bypass escalate overload protection and continue to Layer2")
    void officialVerificationRuns_shouldBypassEscalateProtection() {
        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.4)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("Official verification escalation")
                .shouldEscalate(true)
                .build();

        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .riskScore(0.7)
                .confidence(0.8)
                .action(ZeroTrustAction.CHALLENGE.name())
                .reasoning("Thin evidence requires challenge")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);

        ProcessingResult result = null;
        for (int index = 0; index < 11; index++) {
            SecurityEvent event = SecurityEvent.builder()
                    .userId("user-ov-" + index)
                    .sourceIp("10.0.1." + index)
                    .build();
            event.addMetadata("requestPath", "/api/enterprise/verification/runtime/probe/sensitive/resource-001");
            event.addMetadata("scenario", "OFFICIAL_VERIFICATION_CDC_RESOURCE_SURGE");
            event.addMetadata("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME");
            result = processor.processEvent(event, 0.5);
        }

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name());
        assertThat(result.getReasoning()).isEqualTo("Thin evidence requires challenge");
        assertThat(result.getAnalysisData()).containsEntry("decisionAppliedStage", "LAYER2");
        verify(expertStrategy, times(11)).evaluate(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("escalate rate denominator should include every Layer1 analysis")
    void escalateProtection_shouldUseAllLayer1AnalysesAsDenominator() {
        ThreatAssessment nonEscalatingAssessment = ThreatAssessment.builder()
                .riskScore(0.1)
                .confidence(0.9)
                .action(ZeroTrustAction.ALLOW.name())
                .reasoning("Normal traffic")
                .shouldEscalate(false)
                .build();
        ThreatAssessment escalatingAssessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.4)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("Escalate")
                .shouldEscalate(true)
                .build();
        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .riskScore(0.8)
                .confidence(0.9)
                .action(ZeroTrustAction.BLOCK.name())
                .reasoning("Confirmed threat")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(nonEscalatingAssessment);
        for (int index = 0; index < 20; index++) {
            SecurityEvent event = SecurityEvent.builder()
                    .userId("ratio-user")
                    .sourceIp("10.0.4.1")
                    .build();
            event.addMetadata("requestPath", "/api/ratio");
            processor.processEvent(event, 0.1);
        }

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(escalatingAssessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);
        ProcessingResult result = null;
        for (int index = 0; index < 11; index++) {
            SecurityEvent event = SecurityEvent.builder()
                    .userId("ratio-user")
                    .sourceIp("10.0.4.1")
                    .build();
            event.addMetadata("requestPath", "/api/ratio");
            result = processor.processEvent(event, 0.6);
        }

        assertThat(result).isNotNull();
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.BLOCK.name());
        verify(expertStrategy, times(11)).evaluate(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("escalate overload protection should be isolated by tenant and scenario")
    void escalateProtection_shouldBeIsolatedByTenantAndScenario() {
        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.4)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("Escalate")
                .shouldEscalate(true)
                .build();

        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .riskScore(0.8)
                .confidence(0.9)
                .action(ZeroTrustAction.BLOCK.name())
                .reasoning("Confirmed tenant-scoped threat")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);

        for (int index = 0; index < 11; index++) {
            SecurityEvent event = SecurityEvent.builder()
                    .userId("tenant-a-user-" + index)
                    .sourceIp("10.0.2." + index)
                    .build();
            event.addMetadata("tenantId", "tenant-a");
            event.addMetadata("scenario", "EXPORT_SURGE");
            event.addMetadata("requestPath", "/api/export");
            processor.processEvent(event, 0.5);
        }

        SecurityEvent tenantBEvent = SecurityEvent.builder()
                .userId("tenant-b-user")
                .sourceIp("10.0.3.1")
                .build();
        tenantBEvent.addMetadata("tenantId", "tenant-b");
        tenantBEvent.addMetadata("scenario", "EXPORT_SURGE");
        tenantBEvent.addMetadata("requestPath", "/api/export");

        ProcessingResult result = processor.processEvent(tenantBEvent, 0.5);

        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.BLOCK.name());
        verify(expertStrategy, times(11)).evaluate(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("Missing userId should return failure result")
    void missingUserId_shouldReturnFailure() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId(null)
                .sourceIp("10.0.0.4")
                .build();

        // when
        ProcessingResult result = processor.processEvent(event, 0.5);

        // then
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getProcessingPath()).isEqualTo(ProcessingResult.ProcessingPath.COLD_PATH);
    }

    @Test
    @DisplayName("getProcessingMode should return AI_ANALYSIS")
    void getProcessingMode_shouldReturnAiAnalysis() {
        // when
        ProcessingMode mode = processor.getProcessingMode();

        // then
        assertThat(mode).isEqualTo(ProcessingMode.AI_ANALYSIS);
    }
}
