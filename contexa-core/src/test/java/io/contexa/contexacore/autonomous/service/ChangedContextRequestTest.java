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
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.AsyncProtectableGate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A person's request from another session, address or browser than the user's decision was reached for is answered
 * after its verdict: the first requests of a stolen session used from elsewhere do not go out before the model has seen
 * them. The requests of the context on record go on as they did, with the verdict after the response.
 */
class ChangedContextRequestTest {

    private static final String USER = "alice";
    private static final String HOME = "context-home";
    private static final String ELSEWHERE = "context-elsewhere";
    private static final Duration WAIT = Duration.ofMillis(200);
    /** Far longer than a store that is down may hold a request. */
    private static final Duration LONG_WAIT = Duration.ofSeconds(5);
    private static final Duration WHILE_DOWN = Duration.ofMillis(100);
    private static final int AT_ONCE = 8;

    private final AdjustableClock clock = new AdjustableClock();
    private final AtomicBoolean recordUnreadable = new AtomicBoolean();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock) {
                @Override
                public String decidedContext(String userId) {
                    if (recordUnreadable.get()) {
                        throw new QueryTimeoutException("Redis command timed out");
                    }
                    return super.decidedContext(userId);
                }
            };
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final ZeroTrustEventListener listener = new ZeroTrustEventListener(mock(SecurityEventPublisher.class),
            repository, new SecurityZeroTrustProperties());
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final UnanalysedRequestRecorder recorder = mock(UnanalysedRequestRecorder.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final Authentication alice = new UsernamePasswordAuthenticationToken(USER, "n/a");
    /** The facts of the request the calling thread makes. */
    private final ThreadLocal<Map<String, Object>> request = new ThreadLocal<>();
    private final AtomicInteger asked = new AtomicInteger();
    private final AtomicBoolean verdictStored = new AtomicBoolean();
    private volatile long modelMillis = 40;
    private SynchronousProtectableDecisionService service;
    private ContexaStores stores;

    @BeforeEach
    void setUp() {
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setDecisionWait(WAIT);
        service.setStoreDownWait(WHILE_DOWN);
        service.setUnanalysedRequestRecorder(recorder);
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenAnswer(call -> event(request.get()));
    }

    @AfterEach
    void tearDown() {
        if (stores != null) {
            stores.destroy();
        }
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("browser").resource("/records/1").payload(payload).build();
    }

    private static Map<String, Object> importance(boolean sensitive) {
        return sensitive ? Map.of("resourceImportance", "SENSITIVE") : Map.of();
    }

    private AsyncProtectableGate gate(String context, Map<String, Object> facts) {
        Map<String, Object> payload = new HashMap<>(facts);
        payload.put("contextBindingHash", context);
        request.set(payload);
        return service.asyncGate(invocation, alice);
    }

    private void decided(String key, ZeroTrustAction action, String context) {
        repository.writeFinalAction(key, action, Map.of("observationId", "observation-1", "processingGeneration", "1",
                "contextBindingHash", context));
    }

    private void decidedEarlier(ZeroTrustAction action, String context) {
        decided(USER, action, context);
    }

    private static SecurityEventContext analysed(ZeroTrustAction action) {
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(SecurityEvent.builder().eventId("event-1").userId(USER).build()).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true).action(action.name()).build());
        return context;
    }

    private void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** The model answers as the engine does: the decision is stored under its context, then the analysis ends. */
    private void theModelAnswers(String key, ZeroTrustAction verdict) {
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            asked.incrementAndGet();
            return CompletableFuture.supplyAsync(() -> {
                pause(modelMillis);
                decided(key, verdict, event.getMetadata().get("contextBindingHash").toString());
                verdictStored.set(true);
                return analysed(verdict);
            });
        });
    }

    private void theModelAnswers(ZeroTrustAction verdict) {
        theModelAnswers(USER, verdict);
    }

    private void theModelDoesNotAnswerInTime() {
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            asked.incrementAndGet();
            return new CompletableFuture<SecurityEventContext>();
        });
    }

    private void theAnalysisFailsWith(Throwable failure) {
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            asked.incrementAndGet();
            return CompletableFuture.failedFuture(failure);
        });
    }

    private void aStoreIsDown() {
        stores = new ContexaStores();
        stores.redis().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        stores.redis().fail(new QueryTimeoutException("no answer"));
        service.setContexaStores(stores);
        service.setDecisionWait(LONG_WAIT);
    }

    private void nothingWasAnalysed() {
        assertThat(asked).hasValue(0);
        verify(agent, never()).processSecurityEventOffThread(any());
        verify(agent, never()).processSecurityEvent(any());
    }

    /** What the store reads for the request after the answer: nothing a request was answered with is stored. */
    private void nothingWasStoredFor(String context) {
        assertThat(repository.getCurrentAction(USER, context)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.decidedContext(USER)).isNotEqualTo(context);
    }

    private void theModelWasAsked() {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (asked.get() == 0) {
            assertThat(System.nanoTime()).as("the model is asked").isLessThan(until);
            Thread.onSpinWait();
        }
    }

    private void noSecondEvent() {
        verify(publisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
    }

    @ParameterizedTest(name = "{0}, sensitive resource: false")
    @EnumSource(value = ZeroTrustAction.class, names = {"CHALLENGE", "BLOCK", "ESCALATE"})
    @DisplayName("a general resource from another context waits for the verdict that stops it")
    void aGeneralResourceWaitsForTheVerdictThatStopsIt(ZeroTrustAction verdict) {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(verdict);

        assertThat(gate(ELSEWHERE, importance(false)).restriction()).isEqualTo(verdict);

        assertThat(asked).hasValue(1);
    }

    @ParameterizedTest(name = "{0}, sensitive resource: true")
    @EnumSource(value = ZeroTrustAction.class, names = {"CHALLENGE", "BLOCK", "ESCALATE"})
    @DisplayName("a sensitive resource from another context waits for the verdict that stops it")
    void aSensitiveResourceWaitsForTheVerdictThatStopsIt(ZeroTrustAction verdict) {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(verdict);

        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(verdict);

        assertThat(asked).hasValue(1);
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("an ALLOW lets it run, asked once and with no second event")
    void anAllowLetsItRunWithoutASecondEvent(boolean sensitive) {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);

        AsyncProtectableGate gate = gate(ELSEWHERE, importance(sensitive));

        assertThat(gate.restriction()).isNull();
        assertThat(gate.passed()).isTrue();
        assertThat(gate.publishesEvent()).as("the analysis that decided it was its event").isFalse();
        assertThat(asked).hasValue(1);
        noSecondEvent();
    }

    @Test
    @DisplayName("the answer comes after the verdict, not before it")
    void theAnswerComesAfterTheVerdict() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);

        gate(ELSEWHERE, importance(false));

        assertThat(verdictStored).isTrue();
    }

    @Test
    @DisplayName("the last verified context counts once the decision is past its TTL")
    void theLastVerifiedContextCounts() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        clock.advance(Duration.ofHours(1));
        theModelAnswers(ZeroTrustAction.CHALLENGE);

        assertThat(gate(ELSEWHERE, importance(false)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("the context on record goes on as it did, past the decision's TTL too")
    void theContextOnRecordGoesOn(boolean sensitive) {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);

        assertThat(gate(HOME, importance(sensitive))).isEqualTo(AsyncProtectableGate.PROCEED);

        clock.advance(Duration.ofHours(1));
        assertThat(gate(HOME, importance(sensitive))).isEqualTo(AsyncProtectableGate.PROCEED);
        nothingWasAnalysed();
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("before the user's first decision there is nothing to compare, and the request goes on as it did")
    void beforeTheFirstDecisionNothingIsCompared(boolean sensitive) {
        assertThat(gate(ELSEWHERE, importance(sensitive))).isEqualTo(AsyncProtectableGate.PROCEED);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a request without a context goes on as it did")
    void aRequestWithoutAContextIsNotCompared() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        clock.advance(Duration.ofHours(1));
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenReturn(ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).resource("/records/1")
                .payload(new HashMap<>()).build());

        assertThat(service.asyncGate(invocation, alice)).isEqualTo(AsyncProtectableGate.PROCEED);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("an agent's request stays with the agents' rule: it is decided in place by the interceptor")
    void anAgentsRequestStaysWithItsRule() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);

        AsyncProtectableGate gate = gate(ELSEWHERE, Map.of("executionSubjectKind", "AUTONOMOUS_AGENT"));

        assertThat(gate).isEqualTo(AsyncProtectableGate.DECIDE_IN_PLACE);
        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a service client is no person: its requests go on as they did")
    void aServiceClientGoesOnAsItDid() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);

        assertThat(gate(ELSEWHERE, Map.of("executionSubjectKind", "SERVICE_CLIENT")))
                .isEqualTo(AsyncProtectableGate.PROCEED);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a console session is compared with its own decisions")
    void aConsoleSessionIsComparedWithItsOwnDecisions() {
        String console = ZeroTrustSubject.CONSOLE_KEY + USER;
        decided(console, ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(console, ZeroTrustAction.CHALLENGE);

        assertThat(gate(ELSEWHERE, Map.of("executionSubjectKind", "CONSOLE_ADMIN")).restriction())
                .isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("where decisions are not enforced nothing is held for one")
    void nothingIsHeldWhereDecisionsAreNotEnforced(boolean sensitive) {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        service.setEnforcing(() -> false);

        assertThat(gate(ELSEWHERE, importance(sensitive))).isEqualTo(AsyncProtectableGate.PROCEED);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a shadow boundary holds nothing")
    void aShadowBoundaryHoldsNothing() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);

        assertThat(gate(ELSEWHERE, Map.of("decisionBoundaryMode", "SHADOW"))).isEqualTo(AsyncProtectableGate.PROCEED);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a restriction in force answers as it did where decisions are not enforced")
    void aRestrictionInForceStillAnswersUnenforced() {
        decidedEarlier(ZeroTrustAction.CHALLENGE, HOME);
        service.setEnforcing(() -> false);

        assertThat(gate(ELSEWHERE, importance(false)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a restriction in force answers before any comparison: the model is not asked")
    void aRestrictionInForceAnswersWithoutTheModel() {
        decidedEarlier(ZeroTrustAction.BLOCK, HOME);

        assertThat(gate(ELSEWHERE, importance(false)).restriction()).isEqualTo(ZeroTrustAction.BLOCK);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("past the wait a general resource goes on, recorded and with no second event; the analysis still decides")
    void pastTheWaitAGeneralResourceGoesOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();

        long began = System.nanoTime();
        AsyncProtectableGate gate = gate(ELSEWHERE, importance(false));
        long waitedMs = (System.nanoTime() - began) / 1_000_000;

        assertThat(gate).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);
        assertThat(waitedMs).isBetween(WAIT.toMillis() - 20, WAIT.toMillis() + 2_000);
        verify(recorder).recordPassed(any(ZeroTrustSpringEvent.class));
        nothingWasStoredFor(ELSEWHERE);
        noSecondEvent();
    }

    @Test
    @DisplayName("past the wait a sensitive resource is refused for itself alone")
    void pastTheWaitASensitiveResourceIsRefused() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();

        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        nothingWasStoredFor(ELSEWHERE);
        assertThat(repository.getCurrentAction(USER, HOME)).as("the user's own session is not touched")
                .isEqualTo(ZeroTrustAction.ALLOW);
        noSecondEvent();
    }

    @Test
    @DisplayName("a context whose verdict did not come is not waited for again: a general resource goes on at once")
    void aContextPastItsWaitGoesOnAtOnce() {
        service.setClock(clock);
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        gate(ELSEWHERE, importance(false));

        long began = System.nanoTime();
        AsyncProtectableGate again = gate(ELSEWHERE, importance(false));
        long waitedMs = (System.nanoTime() - began) / 1_000_000;

        assertThat(again).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);
        assertThat(waitedMs).isLessThan(WAIT.toMillis() / 2);
        assertThat(asked).hasValue(1);
        noSecondEvent();
    }

    @Test
    @DisplayName("nor is a sensitive resource: it is refused at once, for itself alone")
    void aSensitiveResourcePastItsWaitIsRefusedAtOnce() {
        service.setClock(clock);
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        gate(ELSEWHERE, importance(true));

        long began = System.nanoTime();
        AsyncProtectableGate again = gate(ELSEWHERE, importance(true));
        long waitedMs = (System.nanoTime() - began) / 1_000_000;

        assertThat(again.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(waitedMs).isLessThan(WAIT.toMillis() / 2);
        assertThat(asked).hasValue(1);
        nothingWasStoredFor(ELSEWHERE);
    }

    @Test
    @DisplayName("the pause is the context's: another one is asked for and waits")
    void anotherContextStillWaits() {
        service.setClock(clock);
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        gate(ELSEWHERE, importance(false));

        gate("context-third", importance(false));

        assertThat(asked).hasValue(2);
    }

    @Test
    @DisplayName("after a minute the context is asked for again: a model that came back decides it")
    void afterAMinuteTheContextIsAskedForAgain() {
        service.setClock(clock);
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        gate(ELSEWHERE, importance(false));

        clock.advance(Duration.ofSeconds(61));
        gate(ELSEWHERE, importance(false));

        assertThat(asked).hasValue(2);
    }

    @Test
    @DisplayName("a failed analysis is no pause: only a verdict that did not come in time is")
    void aFailedAnalysisIsNoPause() {
        service.setClock(clock);
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theAnalysisFailsWith(new IllegalStateException("broken"));
        gate(ELSEWHERE, importance(false));

        gate(ELSEWHERE, importance(false));

        assertThat(asked).hasValue(2);
    }

    @Test
    @DisplayName("a stricter decision that landed in the wait answers a request that had no verdict of its own")
    void aStricterDecisionThatLandedAnswers() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            decidedEarlier(ZeroTrustAction.BLOCK, ELSEWHERE);
            return new CompletableFuture<SecurityEventContext>();
        });

        assertThat(gate(ELSEWHERE, importance(false)).restriction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("with no room for the analysis a general resource goes on at once")
    void noRoomLetsAGeneralResourceGoOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theAnalysisFailsWith(new RejectedExecutionException("full"));

        long began = System.nanoTime();
        assertThat(gate(ELSEWHERE, importance(false))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);

        assertThat((System.nanoTime() - began) / 1_000_000).isLessThan(WAIT.toMillis());
    }

    @Test
    @DisplayName("with no room for the analysis a sensitive resource is refused at once")
    void noRoomRefusesASensitiveResource() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theAnalysisFailsWith(new RejectedExecutionException("full"));

        long began = System.nanoTime();
        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat((System.nanoTime() - began) / 1_000_000).isLessThan(WAIT.toMillis());
    }

    @Test
    @DisplayName("an analysis that fails is no server error: a general resource goes on")
    void aFailedAnalysisLetsAGeneralResourceGoOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theAnalysisFailsWith(new IllegalStateException("pipeline"));

        assertThat(gate(ELSEWHERE, importance(false))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);
    }

    @Test
    @DisplayName("an analysis that fails is no server error: a sensitive resource is refused")
    void aFailedAnalysisRefusesASensitiveResource() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theAnalysisFailsWith(new IllegalStateException("pipeline"));

        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a CHALLENGE no model decided is the verdict of a model that failed, for a general resource too")
    void aTechnicalChallengeIsTheVerdict() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            repository.writeFinalAction(USER, ZeroTrustAction.CHALLENGE, Map.of("observationId", "observation-2",
                    "processingGeneration", "2", "contextBindingHash", ELSEWHERE, "technicalChallenge", true));
            return CompletableFuture.completedFuture(analysed(ZeroTrustAction.CHALLENGE));
        });

        assertThat(gate(ELSEWHERE, importance(false)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.isTechnicalChallenge(USER)).isTrue();
    }

    @Test
    @DisplayName("a store that is down ends the wait: a general resource goes on, as the operating mode specifies")
    void aStoreDownLetsAGeneralResourceGoOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        aStoreIsDown();
        theModelDoesNotAnswerInTime();

        long began = System.nanoTime();
        assertThat(gate(ELSEWHERE, importance(false))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);

        assertThat((System.nanoTime() - began) / 1_000_000).isLessThan(LONG_WAIT.toMillis() / 2);
    }

    @Test
    @DisplayName("a store that is down never lets a sensitive resource through: it is told to come back")
    void aStoreDownRefusesASensitiveResource() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        aStoreIsDown();
        theModelDoesNotAnswerInTime();

        long began = System.nanoTime();
        assertThatThrownBy(() -> gate(ELSEWHERE, importance(true)))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class, denied -> {
                    assertThat(denied.getHttpStatus()).isEqualTo(429);
                    assertThat(denied.getBusyRetryAfterSeconds()).isEqualTo(5);
                });

        assertThat((System.nanoTime() - began) / 1_000_000).isLessThan(LONG_WAIT.toMillis() / 2);
    }

    @Test
    @DisplayName("an analysis a store ended never lets a sensitive resource through")
    void anAnalysisAStoreEndedRefusesASensitiveResource() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        aStoreIsDown();
        theAnalysisFailsWith(new QueryTimeoutException("no answer"));

        assertThatThrownBy(() -> gate(ELSEWHERE, importance(true)))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        denied -> assertThat(denied.getHttpStatus()).isEqualTo(429));
    }

    @Test
    @DisplayName("an analysis a store ended lets a general resource go on")
    void anAnalysisAStoreEndedLetsAGeneralResourceGoOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        aStoreIsDown();
        theAnalysisFailsWith(new QueryTimeoutException("no answer"));

        assertThat(gate(ELSEWHERE, importance(false))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("a restriction the model decided answers though the store did not take it")
    void aRestrictionTheStoreDidNotTakeAnswers(boolean sensitive) {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            call.<SecurityEvent>getArgument(0).addMetadata(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT,
                    ProcessingResult.builder().success(true).action("BLOCK").build());
            return CompletableFuture.failedFuture(new IllegalStateException("no final result"));
        });

        assertThat(gate(ELSEWHERE, importance(sensitive)).restriction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("an ALLOW the store did not take is no verdict: a sensitive resource does not pass on it")
    void anAllowTheStoreDidNotTakeIsNoVerdict() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            call.<SecurityEvent>getArgument(0).addMetadata(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT,
                    ProcessingResult.builder().success(true).action("ALLOW").build());
            return CompletableFuture.failedFuture(new IllegalStateException("no final result"));
        });

        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a record that cannot be read tells nothing: a general resource goes on as it did, and the model is not asked")
    void anUnreadableRecordLetsAGeneralResourceGoOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        clock.advance(Duration.ofHours(1));
        recordUnreadable.set(true);

        assertThat(gate(HOME, importance(false))).isEqualTo(AsyncProtectableGate.PROCEED);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a record that cannot be read tells nothing: a sensitive resource does not go without a verdict")
    void anUnreadableRecordHoldsASensitiveResource() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        clock.advance(Duration.ofHours(1));
        aStoreIsDown();
        recordUnreadable.set(true);
        theModelDoesNotAnswerInTime();

        assertThatThrownBy(() -> gate(HOME, importance(true)))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        denied -> assertThat(denied.getHttpStatus()).isEqualTo(429));
    }

    @Test
    @DisplayName("a verdict that comes while the record cannot be read answers a sensitive resource")
    void aVerdictAnswersWhileTheRecordCannotBeRead() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        clock.advance(Duration.ofHours(1));
        recordUnreadable.set(true);
        theModelAnswers(ZeroTrustAction.ALLOW);

        assertThat(gate(HOME, importance(true))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);
    }

    @Test
    @DisplayName("a decision that waits for its audit record is not asked for again: a general resource goes on")
    void aDecisionWaitingForItsAuditLetsAGeneralResourceGoOn() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        repository.markDecisionAuditPending(USER, ELSEWHERE, Duration.ofMinutes(1));

        assertThat(gate(ELSEWHERE, importance(false))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("a decision that waits for its audit record is not asked for again: a sensitive resource is refused")
    void aDecisionWaitingForItsAuditRefusesASensitiveResource() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        repository.markDecisionAuditPending(USER, ELSEWHERE, Duration.ofMinutes(1));

        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        nothingWasAnalysed();
    }

    @Test
    @DisplayName("while the analysis is behind a changed context still asks for its own verdict, on the longer wait")
    void whileBehindAChangedContextAsksForItsVerdict() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        when(agent.isBehind()).thenReturn(true);
        theModelAnswers(ZeroTrustAction.ALLOW);

        assertThat(gate(ELSEWHERE, importance(true))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);

        assertThat(asked).hasValue(1);
        noSecondEvent();
    }

    @Test
    @DisplayName("while the analysis is behind a sensitive resource of the context on record waits a moment, as it did")
    void whileBehindTheContextOnRecordWaitsAMoment() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        clock.advance(Duration.ofHours(1));
        when(agent.isBehind()).thenReturn(true);
        service.setBehindWait(Duration.ofMillis(50));

        assertThat(gate(HOME, importance(true)).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        nothingWasAnalysed();
        verify(publisher).publishMethodAuthorization(any(), any(), anyBoolean(), any(),
                eq(ZeroTrustEventPublisher.METHOD_NOT_RUN), any());
    }

    @Test
    @DisplayName("the ALLOW of the new context answers its next request without a wait")
    void theAllowOfTheNewContextAnswersItsNextRequest() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
        gate(ELSEWHERE, importance(false));

        assertThat(gate(ELSEWHERE, importance(true))).isEqualTo(AsyncProtectableGate.PROCEED);

        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("two devices take turns on the one decision of the user: each change of device is a new verdict")
    void twoDevicesTakeTurns() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);

        gate(ELSEWHERE, importance(false));
        gate(HOME, importance(false));
        gate(ELSEWHERE, importance(false));

        assertThat(asked).hasValue(3);
    }

    private List<AsyncProtectableGate> atOnce(String context, Map<String, Object> facts, boolean spread) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(AT_ONCE);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<AsyncProtectableGate>> answers = new ArrayList<>();
            for (int i = 0; i < AT_ONCE; i++) {
                answers.add(pool.submit(() -> {
                    start.await();
                    if (spread) {
                        pause(ThreadLocalRandom.current().nextLong(modelMillis + 15));
                    }
                    AsyncProtectableGate gate = gate(context, facts);
                    assertThat(verdictStored).as("no answer goes out before the verdict").isTrue();
                    return gate;
                }));
            }
            start.countDown();
            List<AsyncProtectableGate> gates = new ArrayList<>();
            for (Future<AsyncProtectableGate> answer : answers) {
                gates.add(answer.get(10, TimeUnit.SECONDS));
            }
            return gates;
        } finally {
            pool.shutdownNow();
        }
    }

    @RepeatedTest(25)
    @DisplayName("requests at once ask the model once and all wait for its ALLOW")
    void requestsAtOnceAskOnceForAnAllow() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);

        List<AsyncProtectableGate> gates = atOnce(ELSEWHERE, importance(false), false);

        assertThat(asked).hasValue(1);
        assertThat(gates).filteredOn(gate -> gate == AsyncProtectableGate.PASS_AND_RECORD).as("the one that asked").hasSize(1);
        assertThat(gates).filteredOn(gate -> gate == AsyncProtectableGate.PROCEED).as("the ones the ALLOW answers")
                .hasSize(AT_ONCE - 1);
        verify(recorder, never()).recordPassed(any(ZeroTrustSpringEvent.class));
    }

    @RepeatedTest(25)
    @DisplayName("requests at once all stop at the restriction")
    void requestsAtOnceAllStop() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.CHALLENGE);

        List<AsyncProtectableGate> gates = atOnce(ELSEWHERE, importance(true), false);

        assertThat(asked).hasValue(1);
        assertThat(gates).allSatisfy(gate -> assertThat(gate.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE));
    }

    @RepeatedTest(25)
    @DisplayName("requests that come around the moment of the verdict do not ask again")
    void requestsAroundTheVerdictDoNotAskAgain() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
        modelMillis = 15;
        CompletableFuture<AsyncProtectableGate> first = CompletableFuture.supplyAsync(
                () -> gate(ELSEWHERE, importance(false)));
        theModelWasAsked();

        List<AsyncProtectableGate> gates = atOnce(ELSEWHERE, importance(false), true);

        assertThat(first.get(10, TimeUnit.SECONDS)).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);
        assertThat(asked).hasValue(1);
        assertThat(gates).allSatisfy(gate -> assertThat(gate).isEqualTo(AsyncProtectableGate.PROCEED));
    }

    @Test
    @DisplayName("past the wait the general requests at once go on, and only the first is analysed")
    void requestsAtOncePastTheWait() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        verdictStored.set(true);

        List<AsyncProtectableGate> gates = atOnce(ELSEWHERE, importance(false), false);

        assertThat(asked).hasValue(1);
        assertThat(gates).allSatisfy(gate -> assertThat(gate).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD));
        verify(recorder, times(AT_ONCE)).recordPassed(any(ZeroTrustSpringEvent.class));
    }

    @Test
    @DisplayName("past the wait the sensitive requests at once are refused")
    void sensitiveRequestsAtOncePastTheWait() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        verdictStored.set(true);

        List<AsyncProtectableGate> gates = atOnce(ELSEWHERE, importance(true), false);

        assertThat(gates).allSatisfy(gate -> assertThat(gate.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE));
    }

    @RepeatedTest(10)
    @DisplayName("a general request that follows another's analysis takes its verdict; a sensitive one takes it as well")
    void aSensitiveRequestFollowsTheVerdictOfAGeneralOne() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.BLOCK);
        modelMillis = 60;
        CompletableFuture<AsyncProtectableGate> general = CompletableFuture.supplyAsync(
                () -> gate(ELSEWHERE, importance(false)));
        theModelWasAsked();

        assertThat(gate(ELSEWHERE, importance(true)).restriction()).isEqualTo(ZeroTrustAction.BLOCK);

        assertThat(general.get(10, TimeUnit.SECONDS).restriction()).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(asked).hasValue(1);
    }

    @RepeatedTest(5)
    @DisplayName("past the waiting room a request is told to come back, and none goes out before the verdict")
    void pastTheWaitingRoomARequestIsToldToComeBack() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        service.setAgentDecisionFlights(new AgentDecisionFlights(new AgentDecisionFlights.Settings(false, 3, 2,
                Duration.ofSeconds(1), 0, Set.of())));
        theModelAnswers(ZeroTrustAction.ALLOW);
        modelMillis = 150;
        ExecutorService pool = Executors.newFixedThreadPool(AT_ONCE);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger busy = new AtomicInteger();
        AtomicInteger answeredAfterTheVerdict = new AtomicInteger();
        try {
            List<Future<?>> requests = new ArrayList<>();
            for (int i = 0; i < AT_ONCE; i++) {
                requests.add(pool.submit(() -> {
                    start.await();
                    try {
                        gate(ELSEWHERE, importance(false));
                        assertThat(verdictStored).as("no answer goes out before the verdict").isTrue();
                        answeredAfterTheVerdict.incrementAndGet();
                    } catch (ZeroTrustAccessDeniedException denied) {
                        assertThat(denied.getHttpStatus()).isEqualTo(429);
                        assertThat(denied.getBusyRetryAfterSeconds()).isEqualTo(5);
                        busy.incrementAndGet();
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> request : requests) {
                request.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(answeredAfterTheVerdict).as("the one that asked and the two in the room").hasValue(3);
        assertThat(busy).hasValue(AT_ONCE - 3);
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("each changed context is a question of its own: another context does not take the verdict of this one")
    void anotherContextAsksForItself() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
        modelMillis = 60;
        CompletableFuture<AsyncProtectableGate> first = CompletableFuture.supplyAsync(
                () -> gate(ELSEWHERE, importance(false)));
        theModelWasAsked();

        assertThat(gate("context-third", importance(false))).isEqualTo(AsyncProtectableGate.PASS_AND_RECORD);

        first.get(10, TimeUnit.SECONDS);
        assertThat(asked).hasValue(2);
    }

    @Test
    @DisplayName("without a wait the analysis runs in the request, and the one that follows waits for its end")
    void withoutAWaitTheFollowerWaitsForTheEnd() throws Exception {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        service.setDecisionWait(null);
        when(agent.processSecurityEvent(any())).thenAnswer(call -> {
            asked.incrementAndGet();
            pause(modelMillis);
            decidedEarlier(ZeroTrustAction.ALLOW, ELSEWHERE);
            verdictStored.set(true);
            return analysed(ZeroTrustAction.ALLOW);
        });

        List<AsyncProtectableGate> gates = atOnce(ELSEWHERE, importance(false), false);

        assertThat(asked).hasValue(1);
        assertThat(gates).filteredOn(gate -> gate == AsyncProtectableGate.PROCEED).hasSize(AT_ONCE - 1);
        verify(agent, never()).processSecurityEventOffThread(any());
    }

    @Test
    @DisplayName("nothing of a question that ended stays behind: the next one is asked again")
    void aQuestionThatEndedLeavesNothingBehind() {
        decidedEarlier(ZeroTrustAction.ALLOW, HOME);
        theAnalysisFailsWith(new IllegalStateException("pipeline"));

        gate(ELSEWHERE, importance(false));
        gate(ELSEWHERE, importance(false));

        assertThat(asked).hasValue(2);
    }
}
