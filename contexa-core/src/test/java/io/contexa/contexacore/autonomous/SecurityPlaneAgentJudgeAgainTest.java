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
package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-5 (PR-50): the request whose analysis failed is asked again while the CHALLENGE no model decided lasts, so that a
 * model that is back frees the user without a person's step. It is asked a few times, once at a time for a session, and
 * no more once that CHALLENGE is gone.
 */
class SecurityPlaneAgentJudgeAgainTest {

    private static final Duration SOON = Duration.ofMillis(30);

    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
    private final SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
    private final SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private final AtomicBoolean failing = new AtomicBoolean(true);
    private SecurityPlaneAgent agent;

    @BeforeEach
    void setUp() {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        when(dataStore.claimEventProcessingLease(anyString())).thenCallRealMethod();
        when(dataStore.isEventProcessingOwner(anyString(), any())).thenCallRealMethod();
        when(dataStore.markEventProcessed(anyString(), any())).thenCallRealMethod();
        when(dataStore.releaseEventProcessing(anyString(), any())).thenCallRealMethod();
        when(dataStore.claimEventProcessing(anyString()))
                .thenReturn(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
        when(repository.isTechnicalChallenge("alice")).thenReturn(true);
        when(processor.process(any(SecurityEvent.class))).thenAnswer(invocation -> {
            SecurityEvent event = invocation.getArgument(0);
            if (failing.get()) {
                event.addMetadata(SecurityDecisionEnforcementHandler.JUDGE_AGAIN, true);
            }
            return SecurityEventContext.builder().securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
        });
        agent = new SecurityPlaneAgent(monitor, dataStore, mock(CentralAuditFacade.class), processor, properties,
                Runnable::run);
        agent.setZeroTrustActionRepository(repository);
        agent.setJudgeAgainInterval(SOON);
        agent.initialize();
        agent.start();
    }

    @AfterEach
    void tearDown() {
        agent.shutdown();
    }

    private static SecurityEvent event(String id, String session) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestId", "request-" + id);
        return SecurityEvent.builder().eventId(id).userId("alice").sessionId(session).sourceIp("10.0.0.1")
                .metadata(metadata).build();
    }

    @Test
    void theFailedRequestIsAskedAgainUnderAnIdOfItsOwn() {
        agent.processSecurityEvent(event("event-1", "session-1"));

        ArgumentCaptor<SecurityEvent> asked = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(monitor, timeout(2000)).deferEvent(asked.capture(), anyString());
        SecurityEvent again = asked.getValue();
        // A processed event is not analysed twice: under the same id the final decision on record would answer it.
        assertThat(again.getEventId()).isNotEqualTo("event-1").startsWith("event-1");
        assertThat(again.getUserId()).isEqualTo("alice");
        assertThat(again.getSessionId()).isEqualTo("session-1");
        assertThat(again.getMetadata()).containsEntry("requestId", "request-event-1")
                .doesNotContainKey(SecurityDecisionEnforcementHandler.JUDGE_AGAIN)
                .doesNotContainKey(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN);
    }

    @Test
    void aRequestWithoutThatMarkIsNotAskedAgain() {
        failing.set(false);

        agent.processSecurityEvent(event("event-1", "session-1"));

        verify(monitor, after(200).never()).deferEvent(any(), anyString());
    }

    @Test
    void itIsNotAskedOnceThatChallengeIsGone() {
        when(repository.isTechnicalChallenge("alice")).thenReturn(false);

        agent.processSecurityEvent(event("event-1", "session-1"));

        verify(monitor, after(200).never()).deferEvent(any(), anyString());
    }

    @Test
    void itIsAskedAFewTimesAndNoMore() {
        SecurityEvent event = event("event-1", "session-1");
        for (int attempt = 1; attempt <= SecurityPlaneAgent.JUDGE_AGAIN_TIMES + 2; attempt++) {
            agent.processSecurityEvent(event);
            if (attempt > SecurityPlaneAgent.JUDGE_AGAIN_TIMES) {
                break;
            }
            ArgumentCaptor<SecurityEvent> asked = ArgumentCaptor.forClass(SecurityEvent.class);
            verify(monitor, timeout(2000).times(attempt)).deferEvent(asked.capture(), anyString());
            event = asked.getValue();
        }

        verify(monitor, after(200).times(SecurityPlaneAgent.JUDGE_AGAIN_TIMES)).deferEvent(any(), anyString());
    }

    @Test
    void aSessionHasOneRequestWaitingToBeAskedAgain() {
        agent.processSecurityEvent(event("event-1", "session-1"));
        agent.processSecurityEvent(event("event-2", "session-1"));
        agent.processSecurityEvent(event("event-3", "session-1"));

        verify(monitor, after(300).times(1)).deferEvent(any(), anyString());
    }

    @Test
    void anotherSessionIsAskedOnItsOwn() {
        agent.processSecurityEvent(event("event-1", "session-1"));
        agent.processSecurityEvent(event("event-2", "session-2"));

        verify(monitor, timeout(2000).times(2)).deferEvent(any(), anyString());
    }

    @Test
    void aStoppedAgentAsksNothing() {
        agent.setJudgeAgainInterval(Duration.ofMillis(150));
        agent.processSecurityEvent(event("event-1", "session-1"));
        agent.stop();

        verify(monitor, after(400).never()).deferEvent(any(), anyString());
        verify(monitor, never()).deferEvent(any(), anyString());
    }
}
