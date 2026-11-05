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
package io.contexa.contexaiam.security.xacml.pep.interceptor;

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
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.aop.Pointcut;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A protected method of a person whose session, address or browser changed does not run before the verdict, and runs
 * once with no second event when the verdict allows it. The decision service here is the real one, on the in-memory
 * store: only the model and the publisher are stood in for.
 */
class AuthorizationManagerMethodInterceptorChangedContextTest {

    private static final String USER = "alice";
    private static final String HOME = "context-home";
    private static final String ELSEWHERE = "context-elsewhere";
    private static final int AT_ONCE = 6;

    private final InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final ProtectableRapidReentryGuard rapidReentryGuard = mock(ProtectableRapidReentryGuard.class);
    private final MethodInvocation methodInvocation = mock(MethodInvocation.class);
    private final Authentication alice = new UsernamePasswordAuthenticationToken(USER, "n/a", List.of());
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    private final AtomicInteger asked = new AtomicInteger();
    /** The facts of the request the calling thread makes. */
    private final ThreadLocal<Map<String, Object>> request = new ThreadLocal<>();
    private SynchronousProtectableDecisionService service;
    private AuthorizationManagerMethodInterceptor interceptor;
    private ContexaStores stores;

    @BeforeEach
    void setUp() throws Throwable {
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
        ZeroTrustEventListener listener = new ZeroTrustEventListener(mock(SecurityEventPublisher.class), repository, properties);
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setDecisionWait(Duration.ofMillis(150));
        service.setEnforcing(properties::isEnforcementEnabled);
        interceptor = new AuthorizationManagerMethodInterceptor(mock(Pointcut.class),
                mock(ProtectableMethodAuthorizationManager.class), rapidReentryGuard);
        interceptor.setZeroTrustEventPublisher(publisher);
        interceptor.setSynchronousProtectableDecisionService(service);
        interceptor.setSecurityZeroTrustProperties(properties);
        when(rapidReentryGuard.tryAcquire(any(), any(MethodInvocation.class), anyString())).thenReturn(true);
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenAnswer(call -> event(request.get()));
        when(methodInvocation.getMethod()).thenReturn(SampleService.class.getMethod("read"));
        when(methodInvocation.getThis()).thenReturn(new SampleService());
        when(methodInvocation.proceed()).thenReturn("the protected data");
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(alice);
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        repository.removeAllUserData(USER);
        if (stores != null) {
            stores.destroy();
        }
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.2").userAgent("browser").resource("/records/1").payload(payload).build();
    }

    private void aRequestFrom(String context, boolean sensitive) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("contextBindingHash", context);
        if (sensitive) {
            payload.put("resourceImportance", "SENSITIVE");
        }
        request.set(payload);
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
                    Thread.sleep(30);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                decided(verdict, event.getMetadata().get("contextBindingHash").toString());
                return analysed(verdict);
            });
        });
    }

    private void theModelDoesNotAnswerInTime() {
        when(agent.processSecurityEventOffThread(any())).thenAnswer(call -> {
            asked.incrementAndGet();
            return new CompletableFuture<SecurityEventContext>();
        });
    }

    private void aStoreIsDownAndTheAnalysisEnds() {
        stores = new ContexaStores();
        stores.redis().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        stores.redis().fail(new QueryTimeoutException("no answer"));
        service.setContexaStores(stores);
        interceptor.setContexaStores(stores);
        when(agent.processSecurityEventOffThread(any()))
                .thenReturn(CompletableFuture.failedFuture(new QueryTimeoutException("no answer")));
    }

    private void noEventAfterTheCall() {
        verify(publisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
    }

    private void theMethodDidNotRun() throws Throwable {
        verify(methodInvocation, never()).proceed();
    }

    @Test
    @DisplayName("a CHALLENGE of its verdict stops the method before it runs")
    void aChallengeStopsTheMethod() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.CHALLENGE);
        aRequestFrom(ELSEWHERE, false);

        assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        denied -> assertThat(denied.getHttpStatus()).isEqualTo(401));

        theMethodDidNotRun();
        noEventAfterTheCall();
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("a BLOCK of its verdict stops a sensitive method before it runs")
    void aBlockStopsTheMethod() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.BLOCK);
        aRequestFrom(ELSEWHERE, true);

        assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        denied -> assertThat(denied.getHttpStatus()).isEqualTo(403));

        theMethodDidNotRun();
        noEventAfterTheCall();
    }

    @Test
    @DisplayName("an ALLOW of its verdict runs the method once, with no second event and no second question")
    void anAllowRunsTheMethodOnce() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
        aRequestFrom(ELSEWHERE, false);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        verify(methodInvocation, times(1)).proceed();
        noEventAfterTheCall();
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("the context on record runs at once and is decided after the call, as it was")
    void theContextOnRecordIsDecidedAfterTheCall() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        aRequestFrom(HOME, true);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        verify(agent, never()).processSecurityEventOffThread(any());
        verify(publisher).publishMethodAuthorization(eq(methodInvocation), eq(alice), eq(true), isNull(),
                eq(ZeroTrustEventPublisher.METHOD_COMPLETED), isNull());
    }

    @Test
    @DisplayName("the first request of a user with nothing on record runs at once, as it did")
    void aUserWithNothingOnRecordRunsAtOnce() throws Throwable {
        aRequestFrom(ELSEWHERE, true);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        verify(agent, never()).processSecurityEventOffThread(any());
    }

    @Test
    @DisplayName("a repeated call inside the rapid re-entry window is answered, not refused as an agent's is")
    void aRepeatedCallIsAnswered() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
        aRequestFrom(ELSEWHERE, false);
        interceptor.invoke(methodInvocation);
        when(rapidReentryGuard.tryAcquire(any(), any(MethodInvocation.class), anyString())).thenReturn(false);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        verify(methodInvocation, times(2)).proceed();
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("a repeated call inside the window is held for the verdict as the first is, and refused with it")
    void aRepeatedCallIsHeldAsTheFirst() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.CHALLENGE);
        when(rapidReentryGuard.tryAcquire(any(), any(MethodInvocation.class), anyString())).thenReturn(false);
        aRequestFrom(ELSEWHERE, false);

        assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        denied -> assertThat(denied.getHttpStatus()).isEqualTo(401));

        theMethodDidNotRun();
    }

    @RepeatedTest(10)
    @DisplayName("a user's calls at once after a change all run on one verdict, and nothing of the application breaks")
    void callsAtOnceRunOnOneVerdict() throws Exception {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelAnswers(ZeroTrustAction.ALLOW);
        ExecutorService pool = Executors.newFixedThreadPool(AT_ONCE);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Object>> calls = new ArrayList<>();
            for (int i = 0; i < AT_ONCE; i++) {
                calls.add(pool.submit(() -> {
                    start.await();
                    SecurityContext securityContext = mock(SecurityContext.class);
                    when(securityContext.getAuthentication()).thenReturn(alice);
                    SecurityContextHolder.setContext(securityContext);
                    aRequestFrom(ELSEWHERE, false);
                    try {
                        return interceptor.invoke(methodInvocation);
                    } catch (Exception failure) {
                        throw failure;
                    } catch (Throwable failure) {
                        throw new IllegalStateException(failure);
                    }
                }));
            }
            start.countDown();
            for (Future<Object> call : calls) {
                assertThat(call.get(10, TimeUnit.SECONDS)).isEqualTo("the protected data");
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("past the wait a general method runs, with no event after it: the analysis under way is its event")
    void pastTheWaitAGeneralMethodRuns() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        aRequestFrom(ELSEWHERE, false);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        noEventAfterTheCall();
        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("past the wait a sensitive method does not run")
    void pastTheWaitASensitiveMethodDoesNotRun() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        theModelDoesNotAnswerInTime();
        aRequestFrom(ELSEWHERE, true);

        assertThatThrownBy(() -> interceptor.invoke(methodInvocation)).isInstanceOf(ZeroTrustAccessDeniedException.class);

        theMethodDidNotRun();
    }

    @Test
    @DisplayName("an analysis that fails does not fail the application: a general method runs")
    void aFailedAnalysisIsNoServerError() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        when(agent.processSecurityEventOffThread(any()))
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("pipeline")));
        aRequestFrom(ELSEWHERE, false);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");
    }

    @Test
    @DisplayName("with a store down a general method runs and is counted as undecided")
    void aStoreDownLetsAGeneralMethodRun() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        aStoreIsDownAndTheAnalysisEnds();
        List<ContexaStores.UndecidedCalls> records = new ArrayList<>();
        stores.setRecorder(records::add);
        aRequestFrom(ELSEWHERE, false);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        assertThat(records).singleElement().extracting(ContexaStores.UndecidedCalls::calls).isEqualTo(1L);
    }

    @Test
    @DisplayName("with a store down a sensitive method does not run: the caller is told to come back, with no server error")
    void aStoreDownStopsASensitiveMethod() throws Throwable {
        decided(ZeroTrustAction.ALLOW, HOME);
        aStoreIsDownAndTheAnalysisEnds();
        aRequestFrom(ELSEWHERE, true);

        assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class, denied -> {
                    assertThat(denied.getHttpStatus()).isEqualTo(429);
                    assertThat(denied.getBusyRetryAfterSeconds()).isPositive();
                });

        theMethodDidNotRun();
    }

    @Test
    @DisplayName("in SHADOW nothing is held: the method runs at once and is analysed after the call")
    void inShadowNothingIsHeld() throws Throwable {
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
        decided(ZeroTrustAction.ALLOW, HOME);
        aRequestFrom(ELSEWHERE, true);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        verify(agent, never()).processSecurityEventOffThread(any());
        verify(publisher).publishMethodAuthorization(eq(methodInvocation), eq(alice), eq(true), isNull(),
                eq(ZeroTrustEventPublisher.METHOD_COMPLETED), isNull());
    }

    @Test
    @DisplayName("in SHADOW a restriction in force is observed, not enforced, as it was")
    void inShadowARestrictionIsObserved() throws Throwable {
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
        decided(ZeroTrustAction.CHALLENGE, HOME);
        aRequestFrom(ELSEWHERE, false);

        assertThat(interceptor.invoke(methodInvocation)).isEqualTo("the protected data");

        verify(agent, never()).processSecurityEventOffThread(any());
    }

    static class SampleService {
        public String read() {
            return "the protected data";
        }
    }
}
