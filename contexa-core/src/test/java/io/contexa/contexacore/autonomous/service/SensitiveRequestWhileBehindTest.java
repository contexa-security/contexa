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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-23 (PR-81): while the analysis is behind, a sensitive resource does not go without a decision. The request waits a
 * moment for its verdict and is then refused for itself alone; a general resource passes as it did, and nothing changes
 * while the engine keeps up.
 */
class SensitiveRequestWhileBehindTest {

    private static final String USER = "alice";
    private static final String CONTEXT = "context-a";
    private static final Duration A_MOMENT = Duration.ofMillis(120);

    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final ZeroTrustEventListener listener = mock(ZeroTrustEventListener.class);
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final Authentication alice = new UsernamePasswordAuthenticationToken(USER, "n/a");
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setBehindWait(A_MOMENT);
        when(agent.isBehind()).thenReturn(true);
        when(listener.generateAuthorizationContextBindingHash(any())).thenReturn(CONTEXT);
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private void requestFor(Map<String, Object> facts) {
        Map<String, Object> payload = new HashMap<>(facts);
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenReturn(ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("client").resource("/records/1").payload(payload).build());
    }

    private void aSensitiveRequest() {
        requestFor(Map.of("resourceImportance", "SENSITIVE"));
    }

    private SynchronousProtectableDecisionService.AsyncProtectableGate gate() {
        return service.asyncGate(invocation, alice);
    }

    @Test
    void withoutAVerdictItIsRefusedAfterAMoment() {
        aSensitiveRequest();

        long began = System.nanoTime();
        SynchronousProtectableDecisionService.AsyncProtectableGate gate = gate();
        long waitedMs = (System.nanoTime() - began) / 1_000_000;

        assertThat(gate.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(waitedMs).isBetween(A_MOMENT.toMillis() - 20, A_MOMENT.toMillis() + 2_000);
    }

    @Test
    void aSensitivityWordOfTheRequestCountsAsWell() {
        requestFor(Map.of("resourceSensitivity", "HIGH"));

        assertThat(gate().restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    /** Its analysis starts before it waits: the moment is worth waiting only for a verdict that may come. */
    @Test
    void itsAnalysisIsAskedForBeforeItWaits() {
        aSensitiveRequest();

        gate();

        verify(publisher).publishMethodAuthorization(eq(invocation), eq(alice), eq(true), any(),
                eq(ZeroTrustEventPublisher.METHOD_NOT_RUN), any());
    }

    @Test
    void whatItIsRefusedWithIsNotStored() {
        aSensitiveRequest();

        gate();

        verify(repository, never()).saveAction(any(), any(), any());
        verify(repository, never()).writeFinalAction(any(), any(), any());
    }

    @Test
    void aVerdictThatComesInTheMomentAnswersIt() {
        aSensitiveRequest();
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS,
                ZeroTrustAction.PENDING_ANALYSIS, ZeroTrustAction.BLOCK);

        assertThat(gate().restriction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    void anAllowThatComesInTheMomentLetsItRunWithoutASecondEvent() {
        aSensitiveRequest();
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS,
                ZeroTrustAction.ALLOW);

        SynchronousProtectableDecisionService.AsyncProtectableGate gate = gate();

        assertThat(gate.restriction()).isNull();
        assertThat(gate.passed()).isTrue();
        assertThat(gate.publishesEvent()).isFalse();
    }

    @Test
    void aGeneralResourcePassesAsItDid() {
        requestFor(Map.of());

        SynchronousProtectableDecisionService.AsyncProtectableGate gate = gate();

        assertThat(gate).isEqualTo(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);
        verify(publisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
    }

    @Test
    void aSensitiveResourcePassesWhileTheEngineKeepsUp() {
        aSensitiveRequest();
        when(agent.isBehind()).thenReturn(false);

        assertThat(gate()).isEqualTo(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);
    }

    @Test
    void aDecisionInForceAnswersItWithoutAWait() {
        aSensitiveRequest();
        when(repository.getCurrentAction(USER, CONTEXT)).thenReturn(ZeroTrustAction.ALLOW);

        assertThat(gate()).isEqualTo(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);
        verify(publisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
    }

    @Test
    void nothingIsHeldWhereDecisionsAreNotEnforced() {
        aSensitiveRequest();
        service.setEnforcing(() -> false);

        assertThat(gate()).isEqualTo(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);
    }

    @Test
    void aShadowBoundaryHoldsNothing() {
        requestFor(Map.of("resourceImportance", "SENSITIVE", "decisionBoundaryMode", "SHADOW"));

        assertThat(gate()).isEqualTo(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);
    }
}
