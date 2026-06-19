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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityDecisionEnforcementHandlerTest {

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private SecurityLearningService securityLearningService;

    @Mock
    IBlockedUserRecorder blockedUserRecorder;

    @Mock
    private BlockingSignalBroadcaster blockingSignalBroadcaster;
    @Mock
    private AnalysisTriggerStateRepository analysisTriggerStateRepository;
    @Mock
    private HcadEvaluationWriter hcadEvaluationWriter;
    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        handler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository);
    }

    @Test
    @DisplayName("BLOCK decision should save action, set blocked flag, and register block")
    void blockDecision_shouldSaveAndSetBlockedFlag() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-1")
                .sourceIp("10.0.0.1")
                .userAgent("TestAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .riskScore(0.95)
                .confidence(0.9)
                .reasoning("Malicious activity detected")
                .build();
        context.addMetadata("processingResult", processingResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository).saveAction(eq("user-1"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-1");
        verify(blockingSignalBroadcaster).registerBlock("user-1");
    }

    @Test
    @DisplayName("ALLOW decision should trigger learning")
    void allowDecision_shouldTriggerLearning() throws Exception {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-2")
                .sourceIp("10.0.0.2")
                .userAgent("TestAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .riskScore(0.1)
                .confidence(0.95)
                .build();
        context.addMetadata("processingResult", processingResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository).saveAction(eq("user-2"), eq(ZeroTrustAction.ALLOW), anyMap());
        verify(actionRepository, never()).setBlockedFlag(anyString());
    }

    @Test
    @DisplayName("ALLOW decision should schedule baseline learning on the supplied executor")
    void allowDecision_shouldUseConfiguredBaselineLearningExecutor() {
        List<Runnable> submittedTasks = new ArrayList<>();
        Executor capturingExecutor = submittedTasks::add;
        SecurityDecisionEnforcementHandler executorBackedHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository,
                null,
                capturingExecutor);

        SecurityEvent event = SecurityEvent.builder()
                .userId("user-executor")
                .sourceIp("10.0.0.2")
                .userAgent("TestAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .riskScore(0.1)
                .confidence(0.95)
                .build();
        context.addMetadata("processingResult", processingResult);

        boolean result = executorBackedHandler.handle(context);

        assertThat(result).isTrue();
        assertThat(submittedTasks).hasSize(1);
        verify(securityLearningService, never()).learnBaselineOnly(anyString(), any(), any());

        submittedTasks.get(0).run();

        verify(securityLearningService).learnBaselineOnly(eq("user-executor"), any(), eq(event));
    }

    @Test
    @DisplayName("Default handler should accept active context")
    void canHandle_shouldAcceptActiveContext() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-3")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        // when
        boolean canHandle = handler.canHandle(context);

        // then
        assertThat(canHandle).isTrue();
    }

    @Test
    @DisplayName("Failed context with processingResult should still be handled for observation")
    void canHandle_failedContextWithProcessingResult_shouldAcceptForObservation() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-failed-result")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        context.addMetadata("processingResult", ProcessingResult.builder()
                .success(false)
                .message("LLM execution failed")
                .build());
        context.markAsFailed("LLM execution failed");

        boolean canHandle = handler.canHandle(context);

        assertThat(canHandle).isTrue();
    }

    @Test
    @DisplayName("Null processingResult should pass through")
    void nullProcessingResult_shouldPassThrough() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-4")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        // no processingResult in metadata

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository, never()).saveAction(anyString(), any(ZeroTrustAction.class), anyMap());
    }

    @Test
    @DisplayName("pre-trigger completion should release in-flight state after decision enforcement")
    void preTriggerCompletion_shouldReleaseInFlight() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-5")
                .metadata(Map.of(
                        "triggerSource", "PENDING_REDLINE",
                        "triggerStateKey", "trigger-key-1"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .riskScore(0.2)
                .confidence(0.9)
                .build();
        context.addMetadata("processingResult", processingResult);
        boolean result = handler.handle(context);
        assertThat(result).isTrue();
        verify(analysisTriggerStateRepository).releaseInFlight("trigger-key-1");
    }

    @Test
    @DisplayName("HCAD pre-trigger completion should release current in-flight source key")
    void hcadPreTriggerCompletion_shouldReleaseInFlight() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-5b")
                .metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "triggerStateKey", "trigger-key-hcad"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .riskScore(0.2)
                .confidence(0.9)
                .build();
        context.addMetadata("processingResult", processingResult);

        boolean result = handler.handle(context);

        assertThat(result).isTrue();
        verify(analysisTriggerStateRepository).releaseInFlight("trigger-key-hcad");
    }

    @Test
    @DisplayName("getOrder should return 55")
    void getOrder_shouldReturn55() {
        // when
        int order = handler.getOrder();

        // then
        assertThat(order).isEqualTo(55);
    }

    @Test
    @DisplayName("SHADOW mode should skip saveAction, setBlockedFlag, and registerBlock")
    void shadowMode_shouldSkipEnforcementSideEffects() {
        // given
        SecurityZeroTrustProperties shadowProperties = new SecurityZeroTrustProperties();
        shadowProperties.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);

        SecurityDecisionEnforcementHandler shadowHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository,
                shadowProperties);

        SecurityEvent event = SecurityEvent.builder()
                .userId("user-shadow-block")
                .sourceIp("10.0.0.10")
                .userAgent("ShadowAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .riskScore(0.98)
                .confidence(0.95)
                .reasoning("Anomalous behavior detected in shadow")
                .build();
        context.addMetadata("processingResult", processingResult);

        // when
        boolean result = shadowHandler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository, never()).saveAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(actionRepository, never()).setBlockedFlag(anyString());
        verify(blockingSignalBroadcaster, never()).registerBlock(anyString());
    }

    @Test
    @DisplayName("ENFORCE mode with explicit properties should still persist decision")
    void enforceMode_withExplicitProperties_shouldPersist() {
        // given
        SecurityZeroTrustProperties enforceProperties = new SecurityZeroTrustProperties();
        enforceProperties.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);

        SecurityDecisionEnforcementHandler enforceHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository,
                enforceProperties);

        SecurityEvent event = SecurityEvent.builder()
                .userId("user-enforce-block")
                .sourceIp("10.0.0.20")
                .userAgent("EnforceAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .riskScore(0.97)
                .confidence(0.9)
                .reasoning("Enforce path block")
                .build();
        context.addMetadata("processingResult", processingResult);

        // when
        boolean result = enforceHandler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository).saveAction(eq("user-enforce-block"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-enforce-block");
        verify(blockingSignalBroadcaster).registerBlock("user-enforce-block");
    }

    @Test
    @DisplayName("HCAD event-level SHADOW should update evaluation and skip enforcement and learning")
    void hcadEventShadow_shouldUpdateEvaluationAndSkipSideEffects() throws Exception {
        SecurityZeroTrustProperties enforceProperties = new SecurityZeroTrustProperties();
        enforceProperties.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
        List<Runnable> submittedTasks = new ArrayList<>();
        SecurityDecisionEnforcementHandler hcadShadowHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository,
                enforceProperties,
                submittedTasks::add,
                hcadEvaluationWriter);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-hcad-shadow")
                .userId("user-hcad-shadow")
                .sourceIp("10.0.0.30")
                .userAgent("HcadShadowAgent")
                .metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "decisionBoundaryMode", "SHADOW",
                        "hcadMode", "SHADOW",
                        "hcadEvaluationId", "eval-hcad-shadow"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .proposedAction(ZeroTrustAction.CHALLENGE.name())
                .llmAuditRiskScore(0.12d)
                .llmAuditConfidence(0.91d)
                .processingTimeMs(88L)
                .build();
        context.addMetadata("processingResult", processingResult);

        boolean result = hcadShadowHandler.handle(context);

        assertThat(result).isTrue();
        assertThat(submittedTasks).isEmpty();
        verify(actionRepository, never()).saveAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(actionRepository, never()).setBlockedFlag(anyString());
        verify(blockingSignalBroadcaster, never()).registerBlock(anyString());
        verify(securityLearningService, never()).learnBaselineOnly(anyString(), any(), any());
        verify(hcadEvaluationWriter).markDecided(
                eq("eval-hcad-shadow"),
                eq("event-hcad-shadow"),
                eq("ALLOW"),
                eq("CHALLENGE"),
                eq(0.12d),
                eq(0.91d),
                eq(88L),
                eq(null),
                eq(false),
                eq(false),
                eq(null),
                eq(null),
                eq("TP"));
    }

    @Test
    @DisplayName("HCAD non-trigger observation should be recorded as observable false negative when Protectable LLM restricts access")
    void hcadObservationWithoutEvaluationId_shouldRecordFalseNegative() {
        SecurityDecisionEnforcementHandler observationHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository,
                null,
                Runnable::run,
                hcadEvaluationWriter);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-hcad-fn")
                .userId("user-hcad-fn")
                .sourceIp("10.0.0.40")
                .metadata(Map.of(
                        HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true,
                        HcadPreProtectablePromotionAttributes.METADATA_MODE, "SHADOW",
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 45,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "HIGH",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false,
                        "requestId", "request-hcad-fn",
                        "httpMethod", "POST",
                        "requestPath", "/admin/users"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .proposedAction(ZeroTrustAction.BLOCK.name())
                .llmAuditRiskScore(0.91d)
                .llmAuditConfidence(0.87d)
                .processingTimeMs(140L)
                .build();
        context.addMetadata("processingResult", processingResult);

        boolean result = observationHandler.handle(context);

        assertThat(result).isTrue();
        verify(hcadEvaluationWriter).recordObservedDecision(
                eq(event),
                eq("BLOCK"),
                eq("BLOCK"),
                eq(0.91d),
                eq(0.87d),
                eq(140L),
                eq(null),
                eq(false),
                eq(false),
                eq(null),
                eq(null),
                eq("FN"));
    }

    @Test
    @DisplayName("HCAD fallback result should mark evaluation outcome as UNKNOWN")
    void hcadFallbackResult_shouldMarkUnknown() {
        SecurityDecisionEnforcementHandler hcadHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepository,
                null,
                Runnable::run,
                hcadEvaluationWriter);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-hcad-unknown")
                .userId("user-hcad-unknown")
                .metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "hcadEvaluationId", "eval-hcad-unknown"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .technicalFallbackApplied(true)
                .llmDecisionPresent(false)
                .processingTimeMs(17L)
                .build();
        context.addMetadata("processingResult", processingResult);

        boolean result = hcadHandler.handle(context);

        assertThat(result).isTrue();
        verify(hcadEvaluationWriter).markDecided(
                eq("eval-hcad-unknown"),
                eq("event-hcad-unknown"),
                eq("BLOCK"),
                eq(null),
                eq(null),
                eq(null),
                eq(17L),
                eq(null),
                eq(true),
                eq(true),
                eq(null),
                eq(null),
                eq("UNKNOWN"));
    }
}
