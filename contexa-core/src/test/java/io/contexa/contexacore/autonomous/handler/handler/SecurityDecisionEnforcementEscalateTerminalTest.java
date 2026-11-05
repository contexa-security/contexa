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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter.PersistedFinalDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-83: every final decision passes this handler, so a result that names ESCALATE or no action at all, as a processing
 * strategy other than the two layers may leave it, ends here by the Layer2 terminal policy with
 * allow-escalate-final-action off. With it on the handler keeps what it has always done.
 */
class SecurityDecisionEnforcementEscalateTerminalTest {

    private final ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
    private final IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
    private final BlockingSignalBroadcaster blockingSignalBroadcaster = mock(BlockingSignalBroadcaster.class);
    private final AiSecurityDecisionObservationWriter observations = mock(AiSecurityDecisionObservationWriter.class);
    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        when(observations.recordDecision(any(), any(), any())).thenReturn("observation-1");
        when(observations.isStoreConfigured()).thenReturn(true);
        when(actionRepository.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        handler = new SecurityDecisionEnforcementHandler(actionRepository, mock(SecurityLearningService.class),
                blockedUserRecorder, blockingSignalBroadcaster, null, Runnable::run, () -> observations);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "ESCALATE", "E", "NOT_AN_ACTION"})
    void aResultWithoutAFinalActionEndsAsTheTerminalAction(String action) {
        handler.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        ProcessingResult result = result(action);

        assertThat(handler.handle(context(result))).isTrue();

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.CHALLENGE), anyMap());
        verify(actionRepository, never()).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.ESCALATE), anyMap());
        // The handlers after this one, the audit and the decision record read the same action.
        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getTechnicalFallbackApplied()).isTrue();
        assertThat(result.getTechnicalFallbackAction()).isEqualTo("CHALLENGE");
    }

    /** A terminal BLOCK is a BLOCK the enforcement writes in full: its flag, its signal and its record. */
    @Test
    void aTerminalBlockIsEnforcedAsABlock() {
        handler.setEscalateTerminalAction(ZeroTrustAction.BLOCK);

        assertThat(handler.handle(context(result(null)))).isTrue();

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-1");
        verify(blockingSignalBroadcaster).registerBlockAndAwait("user-1");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "BLOCK"})
    void aModelsDecisionPassesUntouched(String action) {
        handler.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        ProcessingResult result = result(action);

        assertThat(handler.handle(context(result))).isTrue();

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.valueOf(action)), anyMap());
        assertThat(result.getAction()).isEqualTo(action);
        assertThat(result.getTechnicalFallbackApplied()).isNull();
    }

    /** A decision the layers already ended is not ended twice: its own record stands. */
    @Test
    void aTerminalizedDecisionKeepsItsRecord() {
        handler.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        ProcessingResult result = ProcessingResult.builder().success(true).action("CHALLENGE")
                .proposedAction("ESCALATE").technicalFallbackApplied(true).technicalFallbackCategory("ReactiveException")
                .technicalFallbackAction("CHALLENGE").reasoning("Layer 2 LLM call failed").build();

        assertThat(handler.handle(context(result))).isTrue();

        assertThat(result.getTechnicalFallbackCategory()).isEqualTo("ReactiveException");
        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.CHALLENGE), anyMap());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"ESCALATE"})
    void anAllowedFinalEscalateStays(String action) {
        ProcessingResult result = result(action);

        assertThat(handler.handle(context(result))).isTrue();

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.ESCALATE), anyMap());
        assertThat(result.getAction()).isEqualTo(action);
        assertThat(result.getTechnicalFallbackApplied()).isNull();
    }

    /** A retry restores the final decision an earlier version recorded; an ESCALATE among them ends as well. */
    @Test
    void aRestoredEscalateEndsAsTheTerminalAction() {
        handler.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        handler.restoreFinalDecision(event(), persisted("ESCALATE"));

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.CHALLENGE), anyMap());
        verify(actionRepository, never()).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.ESCALATE), anyMap());
    }

    @Test
    void aRestoredDecisionOtherThanEscalateStays() {
        handler.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        handler.restoreFinalDecision(event(), persisted("BLOCK"));

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-1");
    }

    @Test
    void aRestoredEscalateStaysWhenAFinalEscalateIsAllowed() {
        handler.restoreFinalDecision(event(), persisted("ESCALATE"));

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.ESCALATE), anyMap());
    }

    private static PersistedFinalDecision persisted(String action) {
        return new PersistedFinalDecision("observation-1", null, "user-1", action, "context-1", "generation-1",
                "request-1");
    }

    private static ProcessingResult result(String action) {
        return ProcessingResult.builder().success(true).action(action).reasoning("a strategy's result").build();
    }

    private static SecurityEvent event() {
        return SecurityEvent.builder().eventId("event-1").userId("user-1").sourceIp("10.0.0.1").userAgent("TestAgent")
                .build();
    }

    private static SecurityEventContext context(ProcessingResult result) {
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event()).build();
        context.addMetadata("processingResult", result);
        return context;
    }
}
