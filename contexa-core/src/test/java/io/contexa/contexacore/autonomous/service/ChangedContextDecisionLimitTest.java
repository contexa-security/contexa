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
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Whoever holds a person's session can change the browser string at each call, and each call from a changed context
 * asks the model before it is answered. Past the decisions of a new context allowed in the window the model is not
 * asked: the call is refused with a CHALLENGE of its own, nothing is stored, and the calls of the context on record go
 * on as they did.
 */
class ChangedContextDecisionLimitTest {

    private static final String USER = "alice";
    private static final String HOME = "context-home";
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
    private volatile long modelMillis = 20;
    private NewContextDecisionLimit limit;
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        limit = new NewContextDecisionLimit(new SecurityZeroTrustProperties.NewContextLimit(), null, clock);
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setDecisionWait(WAIT);
        service.setUnanalysedRequestRecorder(recorder);
        service.setNewContextDecisionLimit(limit);
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenAnswer(call -> event(request.get()));
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("browser").resource("/records/1").payload(payload).build();
    }

    private AsyncProtectableGate gate(String context, boolean sensitive) {
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

    private static SecurityEventContext analysed(ZeroTrustAction action) {
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(SecurityEvent.builder().eventId("event-1").userId(USER).build()).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true).action(action.name()).build());
        return context;
    }

    private void theModelAnswers(ZeroTrustAction verdict) {
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            asked.incrementAndGet();
            return CompletableFuture.supplyAsync(() -> {
                try {
                    Thread.sleep(modelMillis);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                decided(verdict, event.getMetadata().get("contextBindingHash").toString());
                return analysed(verdict);
            });
        });
    }

    /** Six calls, each from a browser string of its own, are decided by the model. */
    private void sixNewBrowsers() {
        for (int i = 0; i < 6; i++) {
            assertThat(gate("context-browser-" + i, false).passed()).isTrue();
        }
        assertThat(asked).hasValue(6);
    }

    @ParameterizedTest(name = "sensitive resource: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("the seventh new browser in a minute is refused with a CHALLENGE of its own, and the model is not asked")
    void theSeventhIsRefusedWithoutTheModel(boolean sensitive) {
        sixNewBrowsers();

        AsyncProtectableGate seventh = gate("context-browser-6", sensitive);

        assertThat(seventh.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(seventh.publishesEvent()).isFalse();
        assertThat(asked).hasValue(6);
        assertThat(repository.getCurrentAction(USER, "context-browser-6")).as("nothing is stored for it")
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.decidedContext(USER)).isEqualTo("context-browser-5");
        verify(recorder).record(any(ZeroTrustSpringEvent.class), eq(ZeroTrustAction.CHALLENGE));
    }

    @Test
    @DisplayName("a hundred and twenty new browsers buy six model calls")
    void aHundredAndTwentyBrowsersBuySix() {
        modelMillis = 1;
        for (int i = 0; i < 120; i++) {
            gate("context-rotating-" + i, false);
        }

        assertThat(asked).hasValue(6);
    }

    @Test
    @DisplayName("the context on record goes on as it did, past the limit too")
    void theContextOnRecordGoesOn() {
        sixNewBrowsers();
        gate("context-browser-6", false);

        assertThat(gate("context-browser-5", false)).isEqualTo(AsyncProtectableGate.PROCEED);
        assertThat(gate("context-browser-5", true)).isEqualTo(AsyncProtectableGate.PROCEED);
        assertThat(asked).hasValue(6);
    }

    @Test
    @DisplayName("a restriction in force still answers first")
    void aRestrictionInForceAnswersFirst() {
        sixNewBrowsers();
        decided(ZeroTrustAction.BLOCK, "context-browser-5");

        assertThat(gate("context-browser-7", false).restriction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("once the window has room the model is asked again")
    void onceTheWindowHasRoomTheModelIsAsked() {
        sixNewBrowsers();
        assertThat(gate("context-browser-6", false).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);

        clock.advance(Duration.ofSeconds(61));

        assertThat(gate("context-browser-6", false).passed()).isTrue();
        assertThat(asked).hasValue(7);
    }

    @Test
    @DisplayName("the person's sign-ins take from the same window")
    void signInsTakeFromTheSameWindow() {
        for (int i = 0; i < 6; i++) {
            limit.take(USER, NewContextDecisionLimit.Kind.SIGN_IN);
        }

        assertThat(gate("context-elsewhere", false).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("the calls of one context at once take one decision of the window")
    void callsAtOnceTakeOneDecision() throws Exception {
        modelMillis = 200;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AsyncProtectableGate>> answers = new ArrayList<>();
        try {
            for (int i = 0; i < 8; i++) {
                answers.add(pool.submit(() -> {
                    start.await();
                    return gate("context-page", false);
                }));
            }
            start.countDown();
            for (Future<AsyncProtectableGate> answer : answers) {
                assertThat(answer.get(10, TimeUnit.SECONDS).restriction()).isNull();
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(asked).hasValue(1);

        modelMillis = 1;
        for (int i = 0; i < 5; i++) {
            assertThat(gate("context-next-" + i, false).passed()).isTrue();
        }
        assertThat(gate("context-past", false).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a call that waits for a call refused by the limit is refused as well, never let through")
    void aCallWaitingForARefusedOneIsRefused() throws Exception {
        for (int i = 0; i < 6; i++) {
            limit.take(USER, NewContextDecisionLimit.Kind.CHANGED_CONTEXT);
        }
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean first = new AtomicBoolean(true);
        doAnswer(call -> {
            if (first.compareAndSet(true, false)) {
                release.await(10, TimeUnit.SECONDS);
            }
            return null;
        }).when(recorder).record(any(ZeroTrustSpringEvent.class), eq(ZeroTrustAction.CHALLENGE));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<AsyncProtectableGate> leader = pool.submit(() -> gate("context-stolen", false));
            long refusedBy = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (first.get()) {
                assertThat(System.nanoTime()).as("the first call is refused by the limit").isLessThan(refusedBy);
                Thread.onSpinWait();
            }
            AtomicReference<Thread> waiting = new AtomicReference<>();
            Future<AsyncProtectableGate> follower = pool.submit(() -> {
                waiting.set(Thread.currentThread());
                return gate("context-stolen", false);
            });
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (waiting.get() == null || waiting.get().getState() == Thread.State.RUNNABLE) {
                assertThat(System.nanoTime()).isLessThan(until);
                Thread.onSpinWait();
            }
            release.countDown();

            assertThat(leader.get(10, TimeUnit.SECONDS).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
            assertThat(follower.get(10, TimeUnit.SECONDS).restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        } finally {
            pool.shutdownNow();
        }
        assertThat(asked).hasValue(0);
        verify(recorder, never()).recordPassed(any(ZeroTrustSpringEvent.class));
        verify(recorder, atLeast(2)).record(any(ZeroTrustSpringEvent.class), eq(ZeroTrustAction.CHALLENGE));
    }

    @Test
    @DisplayName("while a store is down a call past the limit is told to come back, as no verification could be kept")
    void whileAStoreIsDownItIsToldToComeBack() {
        for (int i = 0; i < 6; i++) {
            limit.take(USER, NewContextDecisionLimit.Kind.CHANGED_CONTEXT);
        }
        ContexaStores stores = new ContexaStores();
        try {
            stores.redis().watchWith(() -> {
                throw new IllegalStateException("still down");
            });
            stores.redis().fail(new QueryTimeoutException("no answer"));
            service.setContexaStores(stores);

            assertThatThrownBy(() -> gate("context-elsewhere", false))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                            denied -> assertThat(denied.getHttpStatus()).isEqualTo(429));
        } finally {
            stores.destroy();
        }
        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("without a limit every changed context is asked, as before")
    void withoutALimitEveryContextIsAsked() {
        SecurityZeroTrustProperties.NewContextLimit none = new SecurityZeroTrustProperties.NewContextLimit();
        none.setDecisions(0);
        service.setNewContextDecisionLimit(new NewContextDecisionLimit(none, null, clock));

        for (int i = 0; i < 10; i++) {
            gate("context-free-" + i, false);
        }

        assertThat(asked).hasValue(10);
    }
}
