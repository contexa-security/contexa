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
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreUnavailableException;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.AgentDecisionRecord;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SynchronousProtectableDecisionServiceTest {

    private static final String USER_ID = "alice";
    private static final String CONTEXT_HASH = "ctx-hash";

    @Mock
    private ZeroTrustEventPublisher eventPublisher;

    @Mock
    private ZeroTrustEventListener eventListener;

    @Mock
    private SecurityPlaneAgent securityPlaneAgent;

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private MethodInvocation methodInvocation;

    private UsernamePasswordAuthenticationToken authentication;
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        authentication = new UsernamePasswordAuthenticationToken(USER_ID, "n/a", List.of());
        service = new SynchronousProtectableDecisionService(
                eventPublisher,
                eventListener,
                securityPlaneAgent,
                actionRepository);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    private void aRequestToBeDecided() {
        aRequestToBeDecided(methodEvent("/admin/reports"));
    }

    /** A request that ends in a failure reads less of the store than one that ends in a decision. */
    private void aRequestToBeDecided(ZeroTrustSpringEvent event) {
        bindRequest(request("/admin/reports"));
        lenient().when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(event);
        lenient().when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        lenient().when(eventListener.shouldPublishSynchronousAuthorizationEvent(event)).thenReturn(true);
        lenient().when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        lenient().when(actionRepository.getAnalysisData(USER_ID)).thenReturn(ZeroTrustActionRepository.ZeroTrustAnalysisData.pending());
    }

    /** What the enforcement leaves on the event when the record of a decision could not be written. */
    private void theStoreDidNotTakeTheDecision(ZeroTrustAction decided) {
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            event.addMetadata(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT,
                    ProcessingResult.builder().success(true).action(decided.name()).build());
            throw new IllegalStateException("Security event pipeline did not produce a final result");
        });
    }

    @Test
    @DisplayName("Q-7: a restriction the model decided stands for this request though the store did not take it")
    void aRestrictionTheStoreDidNotTakeAnswersTheRequest() {
        aRequestToBeDecided();
        theStoreDidNotTakeTheDecision(ZeroTrustAction.BLOCK);

        assertThat(service.analyze(methodInvocation, authentication).action()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("Q-7: an ALLOW the store did not take reads as an outage: the call goes on undecided, without a server error")
    void anAllowTheStoreDidNotTakeIsAnOutage() {
        aRequestToBeDecided();
        theStoreDidNotTakeTheDecision(ZeroTrustAction.ALLOW);

        assertThatThrownBy(() -> service.analyze(methodInvocation, authentication))
                .isInstanceOf(StoreUnavailableException.class);
    }

    @Test
    @DisplayName("Q-7: an analysis a store ended reads as an outage")
    void anAnalysisAStoreEndedIsAnOutage() {
        aRequestToBeDecided();
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenThrow(new RuntimeException(
                "Event processing failed", new CannotCreateTransactionException("no connection")));

        assertThatThrownBy(() -> service.analyze(methodInvocation, authentication))
                .isInstanceOf(StoreUnavailableException.class);
    }

    @Test
    @DisplayName("Q-7: a failure that is not a store's stays what it is")
    void anotherFailureStaysWhatItIs() {
        aRequestToBeDecided();
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class)))
                .thenThrow(new IllegalStateException("a bug"));

        assertThatThrownBy(() -> service.analyze(methodInvocation, authentication))
                .isInstanceOf(IllegalStateException.class).hasMessage("a bug");
    }

    @Test
    @DisplayName("Q-7: no decision while a store is down reads as an outage; with the stores up it stays no decision")
    void noDecisionWhileAStoreIsDown() {
        aRequestToBeDecided();
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(mock(SecurityEventContext.class));

        assertThat(service.analyze(methodInvocation, authentication).action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);

        ContexaStores stores = new ContexaStores();
        stores.redis().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        stores.redis().fail(new QueryTimeoutException("no answer"));
        service.setContexaStores(stores);
        try {
            assertThatThrownBy(() -> service.analyze(methodInvocation, authentication))
                    .isInstanceOf(StoreUnavailableException.class);
        } finally {
            stores.destroy();
        }
    }

    @Test
    @DisplayName("Q-7, A1-5: an agent is never let through without a verdict: an outage refuses it as busy")
    void anAgentIsRefusedAsBusy() {
        aRequestToBeDecided(subjectEvent("DELEGATED_AGENT"));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenThrow(new RuntimeException(
                "Event processing failed", new CannotCreateTransactionException("no connection")));

        assertThatThrownBy(() -> service.analyze(methodInvocation, authentication))
                .isInstanceOf(ZeroTrustAccessDeniedException.class);
    }

    @Test
    @DisplayName("sync Protectable executes one LLM decision")
    void analyze_noPreAnalysis_shouldProcessLlmEvent() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class)))
                .thenReturn(mock(SecurityEventContext.class));

        service.analyze(methodInvocation, authentication);

        verify(securityPlaneAgent).processSecurityEvent(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("sync decision should use final action when proposed action is absent")
    void analyze_processingResultWithoutProposedAction_shouldUseFinalAction() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        ProcessingResult processingResult = ProcessingResult.builder()
                .action(ZeroTrustAction.CHALLENGE.name())
                .build();
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult", processingResult));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        SynchronousProtectableDecisionService.SyncDecisionResult result =
                service.analyze(methodInvocation, authentication);

        assertThat(result.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("sync decision should enforce constrained final action instead of proposed action")
    void analyze_constrainedProcessingResult_shouldUseFinalAction() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        ProcessingResult processingResult = ProcessingResult.builder()
                .action(ZeroTrustAction.CHALLENGE.name())
                .proposedAction(ZeroTrustAction.ALLOW.name())
                .autonomyConstraintApplied(true)
                .build();
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult", processingResult));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        SynchronousProtectableDecisionService.SyncDecisionResult result =
                service.analyze(methodInvocation, authentication);

        assertThat(result.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("PR-86: a decision the store kept out is no answer when the restriction cannot be read back")
    void analyze_keptOutDecisionIsNoAnswerWithoutTheRestriction() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        SecurityEvent decided = SecurityEvent.builder().eventId("event-1").userId(USER_ID).build();
        decided.addMetadata(AgentDecisionRecord.ENFORCEMENT_OUTCOME, AgentDecisionRecord.KEPT_STRICTER);
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getSecurityEvent()).thenReturn(decided);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult",
                ProcessingResult.builder().action(ZeroTrustAction.ALLOW.name()).build()));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        assertThat(service.analyze(methodInvocation, authentication).action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);

        // A request's own restriction kept out stays its answer: it still stops the request and says how to go on.
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult",
                ProcessingResult.builder().action(ZeroTrustAction.CHALLENGE.name()).build()));
        assertThat(service.analyze(methodInvocation, authentication).action()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("Q-15: the synchronous analysis takes the event in on the server clock, as a collector does")
    void analyze_takesTheEventInOnTheServerClock() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class)))
                .thenReturn(mock(SecurityEventContext.class));
        long before = System.currentTimeMillis();

        service.analyze(methodInvocation, authentication);

        ArgumentCaptor<SecurityEvent> analysed = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(securityPlaneAgent).processSecurityEvent(analysed.capture());
        assertThat(analysed.getValue().getMetadata().get(DeletedAccountWriteFence.TAKEN_IN_AT))
                .isInstanceOfSatisfying(Long.class, at -> assertThat(at).isBetween(before, System.currentTimeMillis()));
    }

    private void stubEvent(ZeroTrustSpringEvent event) {
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(eventListener.shouldPublishSynchronousAuthorizationEvent(event)).thenReturn(true);
        lenient().when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(actionRepository.getAnalysisData(USER_ID)).thenReturn(ZeroTrustActionRepository.ZeroTrustAnalysisData.pending());
    }

    @Test
    @DisplayName("a stored CHALLENGE is the restriction in force for an asynchronous Protectable (W1-5)")
    void storedRestriction_returnsStoredChallenge() {
        ZeroTrustSpringEvent event = methodEvent("/api/reports");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.CHALLENGE);

        assertThat(service.storedRestriction(methodInvocation, authentication)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("an ALLOW or pending decision is no restriction")
    void storedRestriction_ignoresAllowAndPending() {
        ZeroTrustSpringEvent event = methodEvent("/api/reports");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH))
                .thenReturn(ZeroTrustAction.ALLOW, ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(service.storedRestriction(methodInvocation, authentication)).isNull();
        assertThat(service.storedRestriction(methodInvocation, authentication)).isNull();
    }

    @Test
    @DisplayName("inside a shadow boundary nothing is enforced")
    void storedRestriction_shadowBoundaryEnforcesNothing() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID)
                .resource("/api/reports")
                .payload(Map.of("decisionBoundaryMode", "SHADOW"))
                .build();
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);

        assertThat(service.storedRestriction(methodInvocation, authentication)).isNull();
    }

    /**
     * docs/agent A7-2 (2026-10-23, user approval): only a restriction in force answers a synchronous request; an
     * ALLOW in force no longer does ({@link ZeroTrustEventListener#shouldPublishSynchronousAuthorizationEvent}).
     */
    @Test
    @DisplayName("a sync request answered by the restriction in force is kept in its session without analysis (N-SES-1)")
    void analyze_restrictionInForce_isRecordedWithoutAnalysis() {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        service.setUnanalysedRequestRecorder(unanalysed);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(eventListener.shouldPublishSynchronousAuthorizationEvent(event)).thenReturn(false);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.CHALLENGE);
        when(actionRepository.getAnalysisData(USER_ID)).thenReturn(ZeroTrustActionRepository.ZeroTrustAnalysisData.pending());

        SynchronousProtectableDecisionService.SyncDecisionResult result =
                service.analyze(methodInvocation, authentication);

        assertThat(result.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
        verify(securityPlaneAgent, never()).processSecurityEvent(any(SecurityEvent.class));
        verify(unanalysed).record(event, ZeroTrustAction.CHALLENGE);
        verify(eventListener, never()).shouldPublishAuthorizationEvent(any());
    }

    @Test
    @DisplayName("an analysed sync request is recorded by its analysis, not here (N-SES-1)")
    void analyze_analysedRequest_isNotRecordedHere() {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        service.setUnanalysedRequestRecorder(unanalysed);
        bindRequest(request("/admin/reports"));
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class)))
                .thenReturn(mock(SecurityEventContext.class));

        service.analyze(methodInvocation, authentication);

        verify(unanalysed, never()).record(any(), any());
    }

    @Test
    @DisplayName("an asynchronous request stopped by the restriction in force is kept in its session (N-SES-1)")
    void storedRestriction_restrictedRequestIsRecorded() {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        service.setUnanalysedRequestRecorder(unanalysed);
        ZeroTrustSpringEvent event = methodEvent("/api/reports");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH))
                .thenReturn(ZeroTrustAction.CHALLENGE, ZeroTrustAction.ALLOW);

        assertThat(service.storedRestriction(methodInvocation, authentication)).isEqualTo(ZeroTrustAction.CHALLENGE);
        // An allowed request runs and reaches the listener, which keeps it (N-SES-1).
        assertThat(service.storedRestriction(methodInvocation, authentication)).isNull();

        verify(unanalysed).record(event, ZeroTrustAction.CHALLENGE);
        verify(unanalysed, never()).record(event, ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("A1-5: an agent request with no decision on record is decided in place, not let through")
    void asyncGate_unrecordedAgentRequestIsDecidedInPlace() {
        ZeroTrustSpringEvent event = subjectEvent("DELEGATED_AGENT");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        SynchronousProtectableDecisionService.AsyncProtectableGate gate = service.asyncGate(methodInvocation, authentication);

        assertThat(gate.decideInPlace()).isTrue();
        assertThat(gate.restriction()).isNull();
        assertThat(service.storedRestriction(methodInvocation, authentication)).isNull();
    }

    @Test
    @DisplayName("A1-5: an autonomous agent is an agent too")
    void asyncGate_unrecordedAutonomousAgentRequestIsDecidedInPlace() {
        ZeroTrustSpringEvent event = subjectEvent("AUTONOMOUS_AGENT");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(service.asyncGate(methodInvocation, authentication).decideInPlace()).isTrue();
    }

    @Test
    @DisplayName("A1-5: a person's request with no decision on record proceeds as before")
    void asyncGate_unrecordedPersonsRequestProceeds() {
        ZeroTrustSpringEvent event = subjectEvent("HUMAN_USER");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        SynchronousProtectableDecisionService.AsyncProtectableGate gate = service.asyncGate(methodInvocation, authentication);

        assertThat(gate.decideInPlace()).isFalse();
        assertThat(gate.restriction()).isNull();
    }

    @Test
    @DisplayName("A1-5: an agent's decision on record is used: an ALLOW proceeds, a CHALLENGE restricts")
    void asyncGate_recordedAgentDecisionIsUsed() {
        ZeroTrustSpringEvent event = subjectEvent("DELEGATED_AGENT");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH))
                .thenReturn(ZeroTrustAction.ALLOW, ZeroTrustAction.CHALLENGE);

        SynchronousProtectableDecisionService.AsyncProtectableGate allowed = service.asyncGate(methodInvocation, authentication);
        SynchronousProtectableDecisionService.AsyncProtectableGate restricted = service.asyncGate(methodInvocation, authentication);

        assertThat(allowed.decideInPlace()).isFalse();
        assertThat(allowed.restriction()).isNull();
        assertThat(restricted.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(restricted.decideInPlace()).isFalse();
    }

    @Test
    @DisplayName("docs/agent A5-2: an agent's request its accountable person confirmed answers the CHALLENGE, for that request only")
    void asyncGate_aConfirmedAgentRequestAnswersTheChallenge() {
        MockHttpServletRequest request = request("/api/reports");
        request.setAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION, "confirmation-1");
        bindRequest(request);
        ZeroTrustSpringEvent agentEvent = subjectEvent("DELEGATED_AGENT");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(agentEvent);
        when(eventListener.generateAuthorizationContextBindingHash(agentEvent)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH))
                .thenReturn(ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK);

        assertThat(service.asyncGate(methodInvocation, authentication).restriction()).isNull();
        // A BLOCK stays a BLOCK.
        assertThat(service.asyncGate(methodInvocation, authentication).restriction()).isEqualTo(ZeroTrustAction.BLOCK);

        // A person's CHALLENGE is answered by the person's own step-up, never by an agent's confirmation.
        ZeroTrustSpringEvent personEvent = subjectEvent("HUMAN_USER");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(personEvent);
        when(eventListener.generateAuthorizationContextBindingHash(personEvent)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.CHALLENGE);
        assertThat(service.asyncGate(methodInvocation, authentication).restriction())
                .isEqualTo(ZeroTrustAction.CHALLENGE);

        // Without the confirmation on the request the agent's CHALLENGE restricts.
        RequestContextHolder.resetRequestAttributes();
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(agentEvent);
        assertThat(service.asyncGate(methodInvocation, authentication).restriction())
                .isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("docs/agent F-1: past what an ALLOW answers, an agent's request is decided in place; a person's proceeds")
    void asyncGate_anAgentsAllowAnswersOnlyAFewResourcesThenTheRequestIsDecidedInPlace() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 2, null);
        service.setAgentAllowReuse(reuse);
        reuse.decided(USER_ID, CONTEXT_HASH, ActionFamily.READ, "/api/customers/1");
        when(eventListener.generateAuthorizationContextBindingHash(any())).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.ALLOW);

        assertThat(gateFor("DELEGATED_AGENT", "/api/customers/2").decideInPlace()).isFalse();
        assertThat(gateFor("DELEGATED_AGENT", "/api/customers/3").decideInPlace()).isTrue();
        // A person's ALLOW answers as before.
        assertThat(gateFor("HUMAN_USER", "/api/customers/9").decideInPlace()).isFalse();
    }

    /**
     * RL-5: for a sensitive resource an agent's ALLOW answers one resource; the second is decided in place, where the
     * general limit would still answer it.
     */
    @Test
    @DisplayName("RL-5: an agent's ALLOW answers one sensitive resource, then the next record is decided in place")
    void asyncGate_anAgentsAllowAnswersOnlyOneSensitiveResource() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        service.setAgentAllowReuse(reuse);
        reuse.decided(USER_ID, CONTEXT_HASH, ActionFamily.READ, "/api/customers/1");
        when(eventListener.generateAuthorizationContextBindingHash(any())).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.ALLOW);

        assertThat(gateFor("DELEGATED_AGENT", "/api/customers/1", "RESTRICTED").decideInPlace()).isFalse();
        assertThat(gateFor("DELEGATED_AGENT", "/api/customers/2", "RESTRICTED").decideInPlace()).isTrue();
        // The same records with no sensitivity declared keep the general limit of three.
        assertThat(gateFor("DELEGATED_AGENT", "/api/customers/2", null).decideInPlace()).isFalse();
        assertThat(gateFor("DELEGATED_AGENT", "/api/customers/3", null).decideInPlace()).isFalse();
    }

    private SynchronousProtectableDecisionService.AsyncProtectableGate gateFor(String subjectKind, String resource) {
        return gateFor(subjectKind, resource, null);
    }

    private SynchronousProtectableDecisionService.AsyncProtectableGate gateFor(String subjectKind, String resource,
                                                                               String sensitivity) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("requestPath", resource);
        payload.put("httpMethod", "GET");
        payload.put("executionSubjectKind", subjectKind);
        if (sensitivity != null) {
            payload.put("resourceSensitivity", sensitivity);
        }
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID)
                .resource(resource)
                .payload(payload)
                .build();
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        return service.asyncGate(methodInvocation, authentication);
    }

    @Test
    @DisplayName("docs/agent A7-3 (CF-25): a request its accountable person confirmed is not decided again in place")
    void asyncGate_aConfirmedAgentRequestWithoutADecisionIsNotDecidedAgainInPlace() {
        ZeroTrustSpringEvent agentEvent = subjectEvent("DELEGATED_AGENT");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(agentEvent);
        when(eventListener.generateAuthorizationContextBindingHash(agentEvent)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS, ZeroTrustAction.PENDING_ANALYSIS, ZeroTrustAction.BLOCK);

        // Without a confirmation the unrecorded agent request is decided in place, as before.
        assertThat(service.asyncGate(methodInvocation, authentication).decideInPlace()).isTrue();

        MockHttpServletRequest request = request("/api/reports");
        request.setAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION, "confirmation-1");
        bindRequest(request);
        SynchronousProtectableDecisionService.AsyncProtectableGate confirmed =
                service.asyncGate(methodInvocation, authentication);
        assertThat(confirmed.decideInPlace()).isFalse();
        assertThat(confirmed.restriction()).isNull();
        // A BLOCK in force stays a BLOCK for a confirmed request.
        assertThat(service.asyncGate(methodInvocation, authentication).restriction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("A1-5: the host can let unrecorded agent requests proceed as a person's do")
    void asyncGate_proceedSettingLetsUnrecordedAgentRequestsThrough() {
        service.setUnrecordedAgentRequest(SecurityZeroTrustProperties.UnrecordedAgentRequest.PROCEED);
        ZeroTrustSpringEvent event = subjectEvent("DELEGATED_AGENT");
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null)).thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(service.asyncGate(methodInvocation, authentication).decideInPlace()).isFalse();
    }

    @Test
    @DisplayName("A1-5: when the model cannot be reached the technical fallback decided in place is the answer")
    void analyze_technicalFallbackIsTheAnswer() {
        MockHttpServletRequest request = request("/api/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/api/reports");
        stubEvent(event);
        ProcessingResult processingResult = ProcessingResult.builder()
                .action(ZeroTrustAction.ESCALATE.name())
                .technicalFallbackApplied(true)
                .technicalFallbackCategory("LLM_UNAVAILABLE")
                .technicalFallbackAction(ZeroTrustAction.ESCALATE.name())
                .build();
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult", processingResult));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        assertThat(service.analyze(methodInvocation, authentication).action()).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    @DisplayName("A1-5: a failed analysis leaves no decision, so the request is not let through")
    void analyze_failedProcessingLeavesNoDecision() {
        MockHttpServletRequest request = request("/api/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/api/reports");
        stubEvent(event);
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult",
                ProcessingResult.failure(ProcessingResult.ProcessingPath.COLD_PATH, "AI analysis failed")));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        assertThat(service.analyze(methodInvocation, authentication).action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private ZeroTrustSpringEvent subjectEvent(String subjectKind) {
        return ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID)
                .resource("/api/reports")
                .payload(Map.of("requestPath", "/api/reports", "executionSubjectKind", subjectKind))
                .build();
    }

    private ZeroTrustSpringEvent methodEvent(String path) {
        return ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID)
                .sessionId("session-1")
                .clientIp("203.0.113.10")
                .userAgent("JUnit")
                .resource(path)
                .payload(Map.of(
                        "httpMethod", "GET",
                        "requestPath", path))
                .build();
    }

    private MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("User-Agent", "JUnit");
        return request;
    }

    @Test
    @DisplayName("a call reads as sensitive as the gate of a call without a decision reads it")
    void aCallReadsAsSensitiveAsTheGateReadsIt() {
        ZeroTrustSpringEvent declared = ZeroTrustSpringEvent.builder(new Object())
                .category(ZeroTrustEventCategory.AUTHORIZATION).eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID).payload(Map.of("resourceImportance", "SENSITIVE")).build();
        ZeroTrustSpringEvent general = ZeroTrustSpringEvent.builder(new Object())
                .category(ZeroTrustEventCategory.AUTHORIZATION).eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID).payload(Map.of()).build();
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(declared, general);

        assertThat(service.sensitive(methodInvocation, authentication)).isTrue();
        assertThat(service.sensitive(methodInvocation, authentication)).isFalse();
    }

    private void bindRequest(MockHttpServletRequest request) {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
