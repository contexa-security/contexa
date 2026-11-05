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
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.FinalActionWrite;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter.PersistedFinalDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-5 (PR-50): the enforcement marks the CHALLENGE no model decided, and only that one. A CHALLENGE the model decided, a
 * response whose format broke but whose action was read among them, stands as it did.
 */
class SecurityDecisionEnforcementTechnicalChallengeTest {

    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private final AiSecurityDecisionObservationWriter writer = mock(AiSecurityDecisionObservationWriter.class);
    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        when(writer.recordDecision(any(), any(), any())).thenReturn("observation-1");
        when(repository.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(FinalActionWrite.APPLIED);
        handler = new SecurityDecisionEnforcementHandler(repository, mock(SecurityLearningService.class),
                mock(IBlockedUserRecorder.class), null, null, Runnable::run, () -> writer);
    }

    private static SecurityEvent event() {
        return SecurityEvent.builder().eventId("event-1").userId("alice").sessionId("session-1").build();
    }

    private static ProcessingResult result(String action, Boolean llmDecisionPresent) {
        return ProcessingResult.builder().success(true).action(action).llmDecisionPresent(llmDecisionPresent).build();
    }

    private void handle(SecurityEvent event, ProcessingResult result) {
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", result);
        handler.handle(context);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> writtenFields(ZeroTrustAction action) {
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(repository).writeFinalAction(eq("alice"), eq(action), fields.capture());
        return fields.getValue();
    }

    @Test
    void aChallengeNoModelDecidedIsMarked() {
        handle(event(), result("CHALLENGE", false));

        assertThat(writtenFields(ZeroTrustAction.CHALLENGE))
                .containsEntry(ZeroTrustActionRepository.TECHNICAL_CHALLENGE, true);
    }

    @Test
    void aChallengeTheModelDecidedIsNotMarked() {
        handle(event(), result("CHALLENGE", true));

        assertThat(writtenFields(ZeroTrustAction.CHALLENGE))
                .doesNotContainKey(ZeroTrustActionRepository.TECHNICAL_CHALLENGE);
    }

    @Test
    void aResultThatDoesNotSayIsNotMarked() {
        handle(event(), result("CHALLENGE", null));

        assertThat(writtenFields(ZeroTrustAction.CHALLENGE))
                .doesNotContainKey(ZeroTrustActionRepository.TECHNICAL_CHALLENGE);
    }

    @Test
    void noOtherActionIsMarked() {
        handle(event(), result("BLOCK", false));

        assertThat(writtenFields(ZeroTrustAction.BLOCK))
                .doesNotContainKey(ZeroTrustActionRepository.TECHNICAL_CHALLENGE);
    }

    @Test
    void aRestoredChallengeNoModelDecidedStaysMarked() {
        SecurityEvent event = event();

        handler.restoreFinalDecision(event, new PersistedFinalDecision("observation-1", null, "alice", "CHALLENGE",
                "context-a", "generation-1", "request-1", null, null, null, false));

        assertThat(writtenFields(ZeroTrustAction.CHALLENGE))
                .containsEntry(ZeroTrustActionRepository.TECHNICAL_CHALLENGE, true)
                .containsEntry(ZeroTrustActionRepository.LLM_DECISION_PRESENT, false);
    }

    @Test
    void aRestoredChallengeTheModelDecidedStaysUnmarked() {
        handler.restoreFinalDecision(event(), new PersistedFinalDecision("observation-1", null, "alice", "CHALLENGE",
                "context-a", "generation-1", "request-1", null, null, null, true));

        assertThat(writtenFields(ZeroTrustAction.CHALLENGE))
                .doesNotContainKey(ZeroTrustActionRepository.TECHNICAL_CHALLENGE)
                .containsEntry(ZeroTrustActionRepository.LLM_DECISION_PRESENT, true);
    }

    @Test
    void anAppliedChallengeNoModelDecidedAsksForAnotherDecision() {
        SecurityEvent event = event();

        handle(event, result("CHALLENGE", false));

        assertThat(event.getMetadata()).containsEntry(SecurityDecisionEnforcementHandler.JUDGE_AGAIN, true);
    }

    @Test
    void oneKeptOutByAStricterActionDoesNot() {
        when(repository.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(FinalActionWrite.KEPT_STRICTER);
        SecurityEvent event = event();

        handle(event, result("CHALLENGE", false));

        assertThat(event.getMetadata()).doesNotContainKey(SecurityDecisionEnforcementHandler.JUDGE_AGAIN);
    }

    @Test
    void aDecisionOfTheModelDoesNot() {
        SecurityEvent event = event();

        handle(event, result("CHALLENGE", true));

        assertThat(event.getMetadata()).doesNotContainKey(SecurityDecisionEnforcementHandler.JUDGE_AGAIN);
    }
}
