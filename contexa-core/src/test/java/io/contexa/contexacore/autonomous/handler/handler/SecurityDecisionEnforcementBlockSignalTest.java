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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Which decisions cut a response in flight (docs/showcase/응답차단-수정계획.md RT-4): only BLOCK registers the block
 * signal, as first designed and as the public documentation states (CHALLENGE and ESCALATE apply from the next
 * request, R-11), and a failed signal publication still records the block before the event fails (R-5).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityDecisionEnforcementBlockSignalTest {

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private SecurityLearningService securityLearningService;

    @Mock
    private IBlockedUserRecorder blockedUserRecorder;

    @Mock
    private BlockingSignalBroadcaster signals;

    @Mock
    private AiSecurityDecisionObservationWriter observationWriter;

    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        when(observationWriter.recordDecision(any(), any(), any())).thenReturn("observation-1");
        when(observationWriter.isStoreConfigured()).thenReturn(true);
        when(actionRepository.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        handler = new SecurityDecisionEnforcementHandler(actionRepository, securityLearningService,
                blockedUserRecorder, signals, null, Runnable::run, () -> observationWriter);
    }

    private static SecurityEventContext decided(ZeroTrustAction action) {
        SecurityEvent event = SecurityEvent.builder().userId("user-1").sourceIp("10.0.0.1").userAgent("TestAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true).action(action.name())
                .riskScore(0.9).confidence(0.9).reasoning("decided " + action).build());
        return context;
    }

    @Test
    @DisplayName("a BLOCK decision sets the blocked flag, then registers the signal, then records the block")
    void aBlockDecisionRegistersTheSignal() {
        assertThat(handler.handle(decided(ZeroTrustAction.BLOCK))).isTrue();

        InOrder order = inOrder(actionRepository, signals, blockedUserRecorder);
        order.verify(actionRepository).writeFinalAction(eq("user-1"), eq(ZeroTrustAction.BLOCK), anyMap());
        order.verify(actionRepository).setBlockedFlag("user-1");
        order.verify(signals).registerBlockAndAwait("user-1");
        order.verify(blockedUserRecorder).recordBlock(any(), eq("user-1"), any(), eq("BLOCK"), any(), any(), any());
    }

    @ParameterizedTest
    @EnumSource(value = ZeroTrustAction.class, names = {"CHALLENGE", "ESCALATE", "ALLOW"})
    @DisplayName("CHALLENGE, ESCALATE and ALLOW never register the signal: they apply from the next request")
    void otherDecisionsDoNotCutTheResponseInFlight(ZeroTrustAction action) {
        assertThat(handler.handle(decided(action))).isTrue();

        verify(actionRepository).writeFinalAction(eq("user-1"), eq(action), anyMap());
        verify(signals, never()).registerBlockAndAwait(anyString());
        verify(signals, never()).registerBlock(anyString());
        verify(signals, never()).registerBlock(anyString(), anyString());
        verify(actionRepository, never()).setBlockedFlag(anyString());
    }

    @Test
    @DisplayName("a failed signal publication still records the block, then fails the event")
    void aFailedPublicationStillRecordsTheBlock() {
        doThrow(new IllegalStateException("redis unavailable")).when(signals).registerBlockAndAwait("user-1");
        SecurityEventContext context = decided(ZeroTrustAction.BLOCK);

        assertThat(handler.handle(context)).isFalse();

        verify(actionRepository).setBlockedFlag("user-1");
        verify(blockedUserRecorder).recordBlock(any(), eq("user-1"), any(), eq("BLOCK"), any(), any(), any());
    }
}
