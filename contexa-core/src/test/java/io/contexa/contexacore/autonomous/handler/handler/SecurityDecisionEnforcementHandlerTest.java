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
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    private AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter;
    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        when(aiSecurityDecisionObservationWriter.recordDecision(any(), any(), any())).thenReturn("observation-1");
        when(aiSecurityDecisionObservationWriter.isStoreConfigured()).thenReturn(true);
        when(actionRepository.saveFinalAction(anyString(), any(ZeroTrustAction.class), anyMap())).thenReturn(true);
        when(actionRepository.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        handler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                null,
                Runnable::run,
                () -> aiSecurityDecisionObservationWriter);
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
        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-1");
        verify(blockingSignalBroadcaster).registerBlockAndAwait("user-1");
    }

    @Test
    @DisplayName("an allowed request the learning promotion holds is held, not learned; another is learned (W5-1)")
    void allowedRequest_heldForPromotionIsNotLearned() {
        LearningPromotionService promotion = mock(LearningPromotionService.class);
        handler.setLearningPromotionService(promotion);
        SecurityEvent held = sessionEvent("request-held");
        SecurityEvent learned = sessionEvent("request-learned");
        when(promotion.holds(held)).thenReturn(true);
        when(promotion.holds(learned)).thenReturn(false);

        handler.handle(contextWith(held, allowed()));
        handler.handle(contextWith(learned, allowed()));

        verify(promotion).hold(held);
        verify(promotion, never()).hold(learned);
        verify(securityLearningService, never()).learnBaselineOnly(anyString(), any(), eq(held));
        verify(securityLearningService).learnBaselineOnly(eq("user-recorded"), any(), eq(learned));
    }

    @Test
    @DisplayName("the promotion is asked before the observations are committed, so the work profile can leave a "
            + "held request out (W5-1)")
    void promotionIsAskedBeforeTheObservationsAreCommitted() {
        ContextObservationRecorder recorder = mock(ContextObservationRecorder.class);
        SecurityDecisionEnforcementHandler recording = recordingHandler(recorder,
                new InMemorySecurityContextDataStore(), new SecurityZeroTrustProperties());
        LearningPromotionService promotion = mock(LearningPromotionService.class);
        recording.setLearningPromotionService(promotion);
        SecurityEvent event = sessionEvent("request-ordered");

        recording.handle(contextWith(event, allowed()));

        InOrder order = inOrder(promotion, recorder);
        order.verify(promotion).holds(event);
        order.verify(recorder).commit(eq(event), any(), anyBoolean());
    }

    @Test
    @DisplayName("an ALLOW kept out by a stricter action in effect is committed as not learnable and not learned (W5-3)")
    void anAllowKeptOutByAStricterActionLearnsNothing() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        List<String> recorded = new ArrayList<>();
        SecurityEvent event = sessionEvent("request-kept");
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, null,
                commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));
        when(actionRepository.writeFinalAction(eq("user-recorded"), eq(ZeroTrustAction.ALLOW), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER);

        recordingHandler(recorder, store, null).handle(contextWith(event, allowed()));

        assertThat(recorded).containsExactly("ALLOW learnable=false");
        verify(securityLearningService, never()).learnBaselineOnly(anyString(), any(), any());
    }

    @Test
    @DisplayName("a result whose processing ownership lapses before its write is neither written nor learned (W5-3)")
    void aResultThatLostItsOwnershipBeforeTheWriteLearnsNothing() {
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);
        // Asked when the result arrives, when its enforcement starts and right before its write.
        when(store.isEventProcessingOwner(anyString(), anyString())).thenReturn(true, true, false);
        SecurityDecisionEnforcementHandler owned = new SecurityDecisionEnforcementHandler(
                actionRepository, securityLearningService, blockedUserRecorder, blockingSignalBroadcaster, null,
                Runnable::run, () -> aiSecurityDecisionObservationWriter, store, null);
        SecurityEvent event = sessionEvent("request-lapsed");
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "identity-lapsed");
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN, "token-lapsed");

        owned.handle(contextWith(event, allowed()));

        verify(actionRepository, never()).writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(actionRepository, never()).saveFinalAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(securityLearningService, never()).learnBaselineOnly(anyString(), any(), any());
    }

    private static ProcessingResult allowed() {
        return ProcessingResult.builder().success(true).action(ZeroTrustAction.ALLOW.name()).riskScore(0.1)
                .confidence(0.9).reasoning("usual work").build();
    }

    @Test
    @DisplayName("the request a restriction stops is held to be learned once the user is verified (W5-2)")
    void restrictionDecision_holdsTheRequestForLearningAfterVerification() {
        VerificationLearningService verification = mock(VerificationLearningService.class);
        handler.setVerificationLearningService(verification);
        for (ZeroTrustAction action : List.of(ZeroTrustAction.CHALLENGE, ZeroTrustAction.ESCALATE,
                ZeroTrustAction.BLOCK, ZeroTrustAction.ALLOW)) {
            SecurityEvent event = SecurityEvent.builder()
                    .userId("user-held")
                    .sourceIp("10.0.0.9")
                    .userAgent("TestAgent")
                    .build();
            event.addMetadata("requestId", "request-" + action.name());
            SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
            context.addMetadata("processingResult", ProcessingResult.builder()
                    .success(true).action(action.name()).riskScore(0.6).confidence(0.8).reasoning("r").build());

            handler.handle(context);

            if (action == ZeroTrustAction.ALLOW) {
                verify(verification, never()).hold(any(), eq(ZeroTrustAction.ALLOW));
            } else {
                verify(verification).hold(event, action);
            }
        }
    }

    @Test
    @DisplayName("a restriction observed in a shadow boundary holds nothing (W5-2)")
    void shadowRestriction_holdsNothing() {
        VerificationLearningService verification = mock(VerificationLearningService.class);
        handler.setVerificationLearningService(verification);
        SecurityEvent event = SecurityEvent.builder().userId("user-shadow").sourceIp("10.0.0.9").userAgent("A").build();
        event.addMetadata("decisionBoundaryMode", "SHADOW");
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", ProcessingResult.builder()
                .success(true).action(ZeroTrustAction.CHALLENGE.name()).riskScore(0.6).confidence(0.8).reasoning("r")
                .build());

        handler.handle(context);

        verify(verification, never()).hold(any(), any());
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
        verify(actionRepository).writeFinalAction(eq("user-2"), eq(ZeroTrustAction.ALLOW), anyMap());
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
                null,
                capturingExecutor,
                () -> aiSecurityDecisionObservationWriter);

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
    @DisplayName("getOrder should return 55")
    void getOrder_shouldReturn55() {
        // when
        int order = handler.getOrder();

        // then
        assertThat(order).isEqualTo(55);
    }

    @Test
    @DisplayName("the final outcome commits the request's context observations once (W2-7)")
    void theFinalOutcomeCommitsTheContextObservationsOnce() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        List<String> recorded = new ArrayList<>();
        SecurityDecisionEnforcementHandler recordingHandler = recordingHandler(recorder, store, null);
        SecurityEvent event = sessionEvent("request-allow");
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, null,
                commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));

        recordingHandler.handle(contextWith(event, ProcessingResult.builder().success(true)
                .action(ZeroTrustAction.ALLOW.name()).build()));
        recordingHandler.handle(contextWith(event, ProcessingResult.builder().success(true)
                .action(ZeroTrustAction.ALLOW.name()).build()));

        assertThat(recorded).containsExactly("ALLOW learnable=true");
        assertThat(store.getRecentSessionDecisions("session-recorded", 10)).hasSize(1);
    }

    @Test
    @DisplayName("a request without a decision keeps its narrative and learns nothing (W2-7)")
    void aRequestWithoutADecisionKeepsItsNarrativeOnly() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        List<String> recorded = new ArrayList<>();
        SecurityEvent failed = sessionEvent("request-failed");
        recorder.stage(failed, ContextObservationRecorder.SESSION_NARRATIVE, null,
                commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));

        recordingHandler(recorder, store, null).handle(contextWith(failed,
                ProcessingResult.builder().success(false).build()));

        assertThat(recorded).containsExactly("null learnable=false");
        assertThat(store.getRecentSessionDecisions("session-recorded", 10)).isEmpty();
    }

    @Test
    @DisplayName("a shadow decision is recorded in the session but learns nothing (W2-7)")
    void aShadowDecisionLearnsNothing() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        List<String> recorded = new ArrayList<>();
        SecurityZeroTrustProperties shadowProperties = new SecurityZeroTrustProperties();
        shadowProperties.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
        SecurityEvent event = sessionEvent("request-shadow");
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, null,
                commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));

        recordingHandler(recorder, store, shadowProperties).handle(contextWith(event,
                ProcessingResult.builder().success(true).action(ZeroTrustAction.ALLOW.name()).build()));

        assertThat(recorded).containsExactly("ALLOW learnable=false");
        assertThat(store.getRecentSessionDecisions("session-recorded", 10)).hasSize(1);
    }

    @Test
    @DisplayName("a restored persisted decision commits the request's context observations under it (W2-7)")
    void aRestoredDecisionCommitsTheContextObservations() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        List<String> recorded = new ArrayList<>();
        SecurityEvent event = sessionEvent("request-restore");
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, null,
                commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));

        recordingHandler(recorder, store, null).restoreFinalDecision(event,
                new AiSecurityDecisionObservationWriter.PersistedFinalDecision("observation-restore", null,
                        "user-recorded", "CHALLENGE", null, "generation-1", "request-restore"));

        assertThat(recorded).containsExactly("CHALLENGE learnable=false");
        assertThat(store.getRecentSessionDecisions("session-recorded", 10)).hasSize(1);
    }

    private SecurityDecisionEnforcementHandler recordingHandler(ContextObservationRecorder recorder,
                                                               InMemorySecurityContextDataStore store,
                                                               SecurityZeroTrustProperties properties) {
        return new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                properties,
                Runnable::run,
                () -> aiSecurityDecisionObservationWriter,
                store,
                recorder);
    }

    private static SecurityEvent sessionEvent(String requestId) {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-recorded")
                .sessionId("session-recorded")
                .sourceIp("10.0.0.20")
                .userAgent("TestAgent")
                .build();
        event.addMetadata("requestId", requestId);
        return event;
    }

    private static SecurityEventContext contextWith(SecurityEvent event, ProcessingResult result) {
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", result);
        return context;
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
                enforceProperties,
                Runnable::run,
                () -> aiSecurityDecisionObservationWriter);

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
        verify(actionRepository).writeFinalAction(eq("user-enforce-block"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-enforce-block");
        verify(blockingSignalBroadcaster).registerBlockAndAwait("user-enforce-block");
    }

    @Test
    @DisplayName("event-level SHADOW should record the LLM observation and skip enforcement and learning")
    void eventShadow_shouldRecordObservationAndSkipSideEffects() throws Exception {
        SecurityZeroTrustProperties enforceProperties = new SecurityZeroTrustProperties();
        enforceProperties.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
        List<Runnable> submittedTasks = new ArrayList<>();
        SecurityDecisionEnforcementHandler eventShadowHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                enforceProperties,
                submittedTasks::add,
                () -> aiSecurityDecisionObservationWriter);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-shadow")
                .userId("user-shadow")
                .sourceIp("10.0.0.30")
                .userAgent("ShadowAgent")
                .metadata(new HashMap<>(Map.of("decisionBoundaryMode", "SHADOW")))
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

        boolean result = eventShadowHandler.handle(context);

        assertThat(result).isTrue();
        assertThat(submittedTasks).isEmpty();
        verify(actionRepository, never()).saveAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(actionRepository, never()).setBlockedFlag(anyString());
        verify(blockingSignalBroadcaster, never()).registerBlock(anyString());
        verify(securityLearningService, never()).learnBaselineOnly(anyString(), any(), any());
        verify(aiSecurityDecisionObservationWriter).recordDecision(event, processingResult, ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("unpersisted observation keeps the decision unenforced, retained for retry and re-analysis suspended")
    void unpersistedObservation_shouldRetainDecisionWithoutEnforcement() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getAnalysis().setAuditFailureCooldownMs(45_000L);
        when(aiSecurityDecisionObservationWriter.recordDecision(any(), any(), any())).thenReturn(null);
        when(aiSecurityDecisionObservationWriter.isStoreConfigured()).thenReturn(false);
        List<Runnable> learningTasks = new ArrayList<>();
        SecurityDecisionEnforcementHandler auditedHandler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                properties,
                learningTasks::add,
                () -> aiSecurityDecisionObservationWriter);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-unaudited")
                .userId("user-unaudited")
                .sessionId("session-unaudited")
                .sourceIp("10.0.0.40")
                .userAgent("AuditAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .reasoning("Decision without audit record")
                .build();
        context.addMetadata("processingResult", processingResult);
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                "session-unaudited", "10.0.0.40", "AuditAgent");

        boolean result = auditedHandler.handle(context);

        assertThat(result).isFalse();
        assertThat(context.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
        verify(actionRepository, never()).saveFinalAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(actionRepository, never()).saveAction(anyString(), any(ZeroTrustAction.class), anyMap());
        verify(actionRepository, never()).setBlockedFlag(anyString());
        verify(blockingSignalBroadcaster, never()).registerBlockAndAwait(anyString());
        verify(actionRepository).markDecisionAuditPending(
                "user-unaudited", contextBindingHash, Duration.ofMillis(45_000L));
        assertThat(learningTasks).isEmpty();
        assertThat(event.getMetadata())
                .containsEntry(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT, processingResult)
                .containsEntry(SecurityPlaneAgent.PROCESSING_FAILURE_REPORTED, true);
    }

    @Test
    @DisplayName("persisted observation of a retained decision enforces it and releases the audit pending marker")
    void persistedRetainedDecision_shouldEnforceAndReleaseMarker() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-recovered")
                .userId("user-recovered")
                .sessionId("session-recovered")
                .sourceIp("10.0.0.41")
                .userAgent("AuditAgent")
                .build();
        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.CHALLENGE.name())
                .build();
        event.addMetadata(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT, processingResult);
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        context.addMetadata("processingResult", processingResult);
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                "session-recovered", "10.0.0.41", "AuditAgent");

        boolean result = handler.handle(context);

        assertThat(result).isTrue();
        verify(actionRepository).writeFinalAction(eq("user-recovered"), eq(ZeroTrustAction.CHALLENGE), anyMap());
        verify(actionRepository).clearDecisionAuditPending("user-recovered", contextBindingHash);
        assertThat(event.getMetadata()).doesNotContainKey(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT);
    }
}
