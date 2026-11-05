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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-54: a synchronous decision holds the application's request thread for a bounded wait. The analysis goes on after
 * it, on the analysis threads, and its verdict is stored for the next request. A request whose verdict did not come in
 * time is not let through, and what it answers is not stored: only this request is refused.
 */
class SynchronousDecisionWaitTest {

    private static final String USER = "alice";
    private static final String CONTEXT = "context-a";
    private static final Duration WAIT = Duration.ofMillis(150);

    private final ZeroTrustEventListener listener = mock(ZeroTrustEventListener.class);
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        service = new SynchronousProtectableDecisionService(mock(ZeroTrustEventPublisher.class), listener, agent,
                repository);
        service.setDecisionWait(WAIT);
        when(listener.generateAuthorizationContextBindingHash(any())).thenReturn(CONTEXT);
        when(listener.shouldPublishSynchronousAuthorizationEvent(any())).thenReturn(true);
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private static ZeroTrustSpringEvent person() {
        return event(Map.of("protectableSync", true));
    }

    private static ZeroTrustSpringEvent agentRequest() {
        return event(Map.of("protectableSync", true, "executionSubjectKind", "AUTONOMOUS_AGENT"));
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("agent").resource("/records/1").payload(payload).build();
    }

    private static SecurityEventContext decided(String action) {
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(SecurityEvent.builder().eventId("event-1").userId(USER).build()).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true).action(action).build());
        return context;
    }

    @Test
    void aVerdictInTimeIsTheAnswer() {
        when(agent.processSecurityEventOffThread(any()))
                .thenReturn(CompletableFuture.completedFuture(decided("ALLOW")));

        assertThat(service.analyze(person()).action()).isEqualTo(ZeroTrustAction.ALLOW);

        verify(agent, never()).processSecurityEvent(any());
    }

    @Test
    void theRequestThreadIsHeldForTheWaitAndNoLonger() {
        when(agent.processSecurityEventOffThread(any())).thenReturn(new CompletableFuture<>());

        long began = System.nanoTime();
        SynchronousProtectableDecisionService.SyncDecisionResult result = service.analyze(person());
        long waitedMs = (System.nanoTime() - began) / 1_000_000;

        assertThat(result.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(waitedMs).isBetween(WAIT.toMillis() - 20, WAIT.toMillis() + 2_000);
        assertThat(result.processingContext()).as("no analysis is reported as finished").isNull();
    }

    @Test
    void whatTheRequestAnswersIsNotStored() {
        when(agent.processSecurityEventOffThread(any())).thenReturn(new CompletableFuture<>());

        service.analyze(person());

        verify(repository, never()).saveAction(any(), any(), any());
        verify(repository, never()).writeFinalAction(any(), any(), any());
    }

    @Test
    void anAllowOfAnEarlierRequestDoesNotLetItThrough() {
        when(agent.processSecurityEventOffThread(any())).thenReturn(new CompletableFuture<>());
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.ALLOW);

        assertThat(service.analyze(person()).action()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    void aStricterDecisionThatLandedMeanwhileIsTheAnswer() {
        when(agent.processSecurityEventOffThread(any())).thenReturn(new CompletableFuture<>());
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.BLOCK);

        assertThat(service.analyze(person()).action()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    void noRoomForTheAnalysisAnswersAtOnce() {
        when(agent.processSecurityEventOffThread(any()))
                .thenReturn(CompletableFuture.failedFuture(new RejectedExecutionException("full")));

        long began = System.nanoTime();
        assertThat(service.analyze(person()).action()).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat((System.nanoTime() - began) / 1_000_000).isLessThan(WAIT.toMillis());
    }

    @Test
    void aFailureOfTheAnalysisStaysTheFailureItWas() {
        when(agent.processSecurityEventOffThread(any()))
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("pipeline")));

        assertThatThrownBy(() -> service.analyze(person()))
                .isInstanceOf(IllegalStateException.class).hasMessage("pipeline");
    }

    @Test
    void anAgentIsToldTheEngineIsBusy() {
        when(agent.processSecurityEventOffThread(any())).thenReturn(new CompletableFuture<>());

        assertThatThrownBy(() -> service.analyze(agentRequest()))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        denied -> assertThat(denied.getBusyRetryAfterSeconds()).isPositive());
    }

    @Test
    void withoutAWaitTheAnalysisRunsInTheRequestAsItDid() {
        service.setDecisionWait(null);
        when(agent.processSecurityEvent(any())).thenReturn(decided("ALLOW"));

        assertThat(service.analyze(person()).action()).isEqualTo(ZeroTrustAction.ALLOW);

        verify(agent, never()).processSecurityEventOffThread(any());
    }
}
