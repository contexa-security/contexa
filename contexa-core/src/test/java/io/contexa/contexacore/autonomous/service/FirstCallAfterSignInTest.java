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
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.AsyncProtectableGate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A person who signs in from a new context is decided once, by the sign-in. The first protected call that follows is
 * from that same context; when it comes before the sign-in's decision is stored, it waits for that decision and is
 * answered by it, as it is answered by any decision of its context in force, instead of asking the model the question
 * the sign-in asked. The wait is bounded; past it the call is decided as it was.
 */
class FirstCallAfterSignInTest {

    private static final String USER = "alice";
    private static final String HOME = "context-home";
    private static final String NEW = "context-new";
    private static final Duration WAIT = Duration.ofSeconds(5);

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final ZeroTrustEventListener listener = new ZeroTrustEventListener(mock(SecurityEventPublisher.class),
            repository, new SecurityZeroTrustProperties());
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final UnanalysedRequestRecorder recorder = mock(UnanalysedRequestRecorder.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final Authentication alice = new UsernamePasswordAuthenticationToken(USER, "n/a");
    private final ThreadLocal<Map<String, Object>> request = new ThreadLocal<>();
    private final AtomicInteger asked = new AtomicInteger();
    private volatile ZeroTrustAction modelVerdict = ZeroTrustAction.ALLOW;
    private NewContextDecisionLimit limit;
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        limit = new NewContextDecisionLimit(new SecurityZeroTrustProperties.NewContextLimit(), null, clock);
        listener.setNewContextDecisionLimit(limit);
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setDecisionWait(WAIT);
        service.setUnanalysedRequestRecorder(recorder);
        service.setNewContextDecisionLimit(limit);
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenAnswer(call -> callEvent(request.get()));
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers();
    }

    private static ZeroTrustSpringEvent callEvent(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("browser").resource("/records/1").payload(payload).build();
    }

    private static ZeroTrustSpringEvent signIn(String user, String nextContext) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId(user).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("browser")
                .payload(new HashMap<>(Map.of("contextBindingHash", nextContext, "authenticationType", "FORM"))).build();
    }

    /** The person signs in from {@code context}: the sign-in is handed to the engine, its decision is not stored yet. */
    private void signsIn(String context) {
        listener.handleZeroTrustEvent(signIn(USER, context));
    }

    private AsyncProtectableGate firstCall(String context, boolean sensitive) {
        Map<String, Object> payload = new HashMap<>();
        if (sensitive) {
            payload.put("resourceImportance", "SENSITIVE");
        }
        payload.put("contextBindingHash", context);
        request.set(payload);
        return service.asyncGate(invocation, alice);
    }

    private void decided(ZeroTrustAction action, String context) {
        repository.writeFinalAction(USER, action, Map.of("observationId", "observation-1", "processingGeneration", "1",
                "contextBindingHash", context));
    }

    /** The sign-in's decision is stored {@code afterMs} from now, as the engine stores one when its analysis ends. */
    private void signInDecisionLandsAfter(long afterMs, ZeroTrustAction action, String context) {
        Thread lands = new Thread(() -> {
            try {
                Thread.sleep(afterMs);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
            decided(action, context);
        }, "sign-in-decision");
        lands.setDaemon(true);
        lands.start();
    }

    private static SecurityEventContext analysed(ZeroTrustAction action) {
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(SecurityEvent.builder().eventId("event-1").userId(USER).build()).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true).action(action.name()).build());
        return context;
    }

    private void theModelAnswers() {
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            asked.incrementAndGet();
            ZeroTrustAction verdict = modelVerdict;
            return CompletableFuture.supplyAsync(() -> {
                try {
                    Thread.sleep(20);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                decided(verdict, event.getMetadata().get("contextBindingHash").toString());
                return analysed(verdict);
            });
        });
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("a first call that comes before the sign-in's decision is stored waits for it and asks the model nothing")
    void theFirstCallWaitsForTheSignInDecision(boolean sensitive) {
        signsIn(NEW);
        signInDecisionLandsAfter(250, ZeroTrustAction.ALLOW, NEW);

        long begun = System.nanoTime();
        AsyncProtectableGate answer = firstCall(NEW, sensitive);
        long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begun);

        assertThat(answer).isEqualTo(AsyncProtectableGate.PROCEED);
        assertThat(asked).as("the sign-in asked the model once; the first call asks it nothing").hasValue(0);
        assertThat(tookMs).as("it waited for the decision, and not longer").isBetween(200L, 2_000L);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "CHALLENGE"})
    @DisplayName("a sign-in decision that restricts is the first call's answer too: the wait never lets a call through")
    void aRestrictionOfTheSignInAnswersTheFirstCall(ZeroTrustAction restriction) {
        signsIn(NEW);
        signInDecisionLandsAfter(250, restriction, NEW);

        AsyncProtectableGate answer = firstCall(NEW, false);

        assertThat(answer.restriction()).isEqualTo(restriction);
        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("a call from another context than the sign-in's is decided as it was")
    void aCallFromAnotherContextIsDecidedAsBefore() {
        signsIn(NEW);

        long begun = System.nanoTime();
        AsyncProtectableGate answer = firstCall("context-elsewhere", false);
        long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begun);

        assertThat(answer.passed()).isTrue();
        assertThat(asked).hasValue(1);
        assertThat(tookMs).as("it did not wait for a sign-in that is not its own").isLessThan(1_000L);
    }

    @Test
    @DisplayName("another person's sign-in from the same context is not waited for")
    void anotherPersonsSignInIsNotWaitedFor() {
        listener.handleZeroTrustEvent(signIn("bob", NEW));

        AsyncProtectableGate answer = firstCall(NEW, false);

        assertThat(answer.passed()).isTrue();
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("a call with no sign-in behind it is decided at once, as it was")
    void aCallWithoutASignInIsDecidedAtOnce() {
        long begun = System.nanoTime();
        AsyncProtectableGate answer = firstCall(NEW, false);
        long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begun);

        assertThat(answer.passed()).isTrue();
        assertThat(asked).hasValue(1);
        assertThat(tookMs).isLessThan(1_000L);
    }

    @Test
    @DisplayName("a sign-in decision that does not come in time is not waited for past the wait: the call is decided as it was")
    void pastTheWaitTheCallIsDecidedAsBefore() {
        service.setBehindWait(Duration.ofMillis(300));
        signsIn(NEW);

        long begun = System.nanoTime();
        AsyncProtectableGate answer = firstCall(NEW, false);
        long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begun);

        assertThat(answer.passed()).isTrue();
        assertThat(asked).as("the call asks the model itself").hasValue(1);
        assertThat(tookMs).as("it waited the wait and no longer").isBetween(250L, 2_000L);
        assertThat(repository.getCurrentAction(USER, NEW)).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("a sign-in decision that comes too late for the wait does not weaken the call: a sensitive call is still decided")
    void aLateSignInDecisionDoesNotWeakenTheCall() {
        service.setBehindWait(Duration.ofMillis(200));
        modelVerdict = ZeroTrustAction.CHALLENGE;
        signsIn(NEW);

        AsyncProtectableGate answer = firstCall(NEW, true);

        assertThat(answer.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("the wait takes no place in the person's decisions of a new context: the sign-in took its own")
    void theWaitTakesNoPlaceInTheLimit() {
        SecurityZeroTrustProperties.NewContextLimit two = new SecurityZeroTrustProperties.NewContextLimit();
        two.setDecisions(2);
        limit = new NewContextDecisionLimit(two, null, clock);
        listener.setNewContextDecisionLimit(limit);
        service.setNewContextDecisionLimit(limit);
        signsIn(NEW);
        signInDecisionLandsAfter(150, ZeroTrustAction.ALLOW, NEW);

        assertThat(firstCall(NEW, false)).isEqualTo(AsyncProtectableGate.PROCEED);

        assertThat(limit.take(USER, NewContextDecisionLimit.Kind.CHANGED_CONTEXT))
                .as("the sign-in took one of the two, the call waited and took none").isTrue();
        assertThat(limit.take(USER, NewContextDecisionLimit.Kind.CHANGED_CONTEXT)).isFalse();
    }

    @Test
    @DisplayName("the calls of the context at once all wait for the one sign-in decision")
    void callsAtOnceAllWaitForTheSignInDecision() throws Exception {
        signsIn(NEW);
        signInDecisionLandsAfter(300, ZeroTrustAction.ALLOW, NEW);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AsyncProtectableGate>> answers = new ArrayList<>();
        try {
            for (int i = 0; i < 8; i++) {
                answers.add(pool.submit(() -> {
                    start.await();
                    return firstCall(NEW, false);
                }));
            }
            start.countDown();
            for (Future<AsyncProtectableGate> answer : answers) {
                assertThat(answer.get(10, TimeUnit.SECONDS).restriction()).isNull();
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("while a store is down nothing is waited for: no decision could be stored, and the call is decided as it was")
    void whileAStoreIsDownNothingIsWaitedFor() {
        service.setBehindWait(Duration.ofSeconds(10));
        signsIn(NEW);
        ContexaStores stores = new ContexaStores();
        try {
            stores.redis().watchWith(() -> {
                throw new IllegalStateException("still down");
            });
            stores.redis().fail(new QueryTimeoutException("no answer"));
            service.setContexaStores(stores);

            long begun = System.nanoTime();
            firstCall(NEW, false);
            long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begun);

            assertThat(tookMs).isLessThan(2_000L);
        } finally {
            stores.destroy();
        }
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("the listener tells that a sign-in decision is on its way for the person and context of the sign-in, and for no other")
    void theListenerKnowsWhichSignInIsOnItsWay() {
        signsIn(NEW);

        assertThat(listener.signInDecisionOnItsWay(callEvent(Map.of()), NEW)).isTrue();
        assertThat(listener.signInDecisionOnItsWay(callEvent(Map.of()), "context-elsewhere")).isFalse();
        assertThat(listener.signInDecisionOnItsWay(callEvent(Map.of()), null)).isFalse();
        assertThat(listener.signInDecisionOnItsWay(null, NEW)).isFalse();
    }

    @Test
    @DisplayName("a sign-in past the person's decisions of a new context is not on its way: it is not analysed")
    void aSignInPastTheLimitIsNotOnItsWay() {
        for (int i = 0; i < 6; i++) {
            limit.take(USER, NewContextDecisionLimit.Kind.SIGN_IN);
        }

        signsIn(NEW);

        assertThat(listener.signInDecisionOnItsWay(callEvent(Map.of()), NEW)).isFalse();
    }

    @Test
    @DisplayName("a call that is not a sign-in's is not mistaken for one")
    void aCallIsNotASignIn() {
        listener.handleZeroTrustEvent(callEvent(new HashMap<>(Map.of("contextBindingHash", NEW))));

        assertThat(listener.signInDecisionOnItsWay(callEvent(Map.of()), NEW)).isFalse();
    }
}
