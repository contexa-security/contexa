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

import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.aop.Pointcut;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthorizationManagerMethodInterceptorTest {

    @Mock
    private Pointcut pointcut;

    @Mock
    private ProtectableMethodAuthorizationManager authorizationManager;

    @Mock
    private ProtectableRapidReentryGuard rapidReentryGuard;

    @Mock
    private ZeroTrustEventPublisher zeroTrustEventPublisher;

    @Mock
    private AuthorizationMetrics metricsCollector;

    @Mock
    private SynchronousProtectableDecisionService synchronousProtectableDecisionService;

    @Mock
    private AuthorizationDenialRecorder authorizationDenialRecorder;

    @Mock
    private MethodInvocation methodInvocation;

    @Mock
    private Authentication authentication;

    private AuthorizationManagerMethodInterceptor interceptor;

    @BeforeEach
    void setUp() throws Exception {
        interceptor = new AuthorizationManagerMethodInterceptor(pointcut, authorizationManager, rapidReentryGuard);
        interceptor.setZeroTrustEventPublisher(zeroTrustEventPublisher);
        interceptor.setMetricsCollector(metricsCollector);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);

        Method method = SampleService.class.getMethod("sampleMethod");
        when(methodInvocation.getMethod()).thenReturn(method);
        when(methodInvocation.getThis()).thenReturn(new SampleService());
    }

    @Nested
    @DisplayName("AOP interception and proceed")
    class InvokeTests {

        @Test
        @DisplayName("Should proceed and return result when authorization passes")
        void shouldProceedWhenAuthorized() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("success");

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("success");
            verify(rapidReentryGuard).tryAcquire(eq(authentication), eq(methodInvocation), anyString());
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
        }

        @Test
        @DisplayName("Should publish authorization event on successful invocation")
        void shouldPublishEventOnSuccess() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("ok");

            interceptor.invoke(methodInvocation);

            verify(zeroTrustEventPublisher).publishMethodAuthorization(
                    eq(methodInvocation), eq(authentication), eq(true), isNull(),
                    eq(ZeroTrustEventPublisher.METHOD_COMPLETED), isNull());
        }

        @Test
        @DisplayName("Should throw AuthenticationCredentialsNotFoundException when no authentication")
        void shouldThrowWhenNoAuthentication() {
            SecurityContext emptyContext = mock(SecurityContext.class);
            when(emptyContext.getAuthentication()).thenReturn(null);
            SecurityContextHolder.setContext(emptyContext);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("Rapid re-entry guard integration")
    class RapidReentryGuardTests {

        @Test
        @DisplayName("Should allow async protectable access and skip event publication on rapid re-entry")
        void shouldAllowAsyncProtectableAndSkipAnalysisOnRapidReentry() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(false);
            when(methodInvocation.proceed()).thenReturn("success");

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("success");
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
            verify(rapidReentryGuard, never()).check(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("ENFORCE should not create another sync LLM decision on actor-session rapid re-entry")
        void enforceSyncProtectableShouldRejectWithoutDuplicateLlmOnRapidReentry() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(false);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(ZeroTrustAccessDeniedException.class);

            verify(rapidReentryGuard, never()).check(any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("SHADOW should proceed and skip duplicate sync LLM decision on actor-session rapid re-entry")
        void shadowSyncProtectableShouldProceedWithoutDuplicateLlmOnRapidReentry() throws Throwable {
            SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
            properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(properties);
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(false);
            when(methodInvocation.proceed()).thenReturn("success");

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("success");
            verify(rapidReentryGuard, never()).check(any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("Deny handling")
    class DenyHandlingTests {

        @Test
        @DisplayName("Should handle policy denial without triggering LLM event publication")
        void shouldHandleAuthorizationDenied() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            AuthorizationDeniedException denied = new AuthorizationDeniedException("denied");
            doThrow(denied).when(authorizationManager).protectable(any(), eq(methodInvocation));

            // Default handler rethrows
            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(AuthorizationDeniedException.class);

            verify(zeroTrustEventPublisher, never())
                    .publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("Should not publish event for ZeroTrustAccessDeniedException")
        void shouldNotPublishEventForZeroTrustDenied() throws Throwable {
            ZeroTrustAccessDeniedException ztDenied =
                    ZeroTrustAccessDeniedException.blocked("SampleService.sampleMethod");
            doThrow(ztDenied).when(authorizationManager).protectable(any(), eq(methodInvocation));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(ZeroTrustAccessDeniedException.class);

            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("Event publishing with metrics")
    class EventPublishingTests {

        @Test
        @DisplayName("Should record metrics when event is published")
        void shouldRecordMetrics() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("ok");

            interceptor.invoke(methodInvocation);

            verify(metricsCollector).recordProtectable(anyLong());
            verify(metricsCollector).recordAuthzDecision();
        }

        @Test
        @DisplayName("Should not fail when event publisher is null")
        void shouldNotFailWhenPublisherIsNull() throws Throwable {
            AuthorizationManagerMethodInterceptor noPublisherInterceptor =
                    new AuthorizationManagerMethodInterceptor(pointcut, authorizationManager, rapidReentryGuard);
            when(methodInvocation.proceed()).thenReturn("ok");

            Object result = noPublisherInterceptor.invoke(methodInvocation);
            assertThat(result).isEqualTo("ok");
        }
    }

    @Nested
    @DisplayName("getOrder()")
    class OrderTests {

        @Test
        @DisplayName("Should return order as FIRST + 1")
        void shouldReturnCorrectOrder() {
            int expected = AuthorizationInterceptorsOrder.FIRST.getOrder() + 1;
            assertThat(interceptor.getOrder()).isEqualTo(expected);
        }
    }

    @Nested
    @DisplayName("Advisor interface methods")
    class AdvisorTests {

        @Test
        @DisplayName("Should return configured pointcut")
        void shouldReturnPointcut() {
            assertThat(interceptor.getPointcut()).isSameAs(pointcut);
        }

        @Test
        @DisplayName("Should return self as advice")
        void shouldReturnSelfAsAdvice() {
            assertThat(interceptor.getAdvice()).isSameAs(interceptor);
        }

        @Test
        @DisplayName("isPerInstance should return true")
        void shouldBePerInstance() {
            assertThat(interceptor.isPerInstance()).isTrue();
        }
    }

    // Sample service used for method reflection in tests
    @Nested
    @DisplayName("Stored decision before an asynchronous Protectable (W1-5)")
    class AsyncStoredDecisionTests {

        @Test
        @DisplayName("ENFORCE mode: a stored CHALLENGE is enforced before the asynchronous method runs")
        void enforce_storedChallengeStopsAsyncMethod() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);
            when(synchronousProtectableDecisionService.asyncGate(methodInvocation, authentication))
                    .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.restricted(ZeroTrustAction.CHALLENGE));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                            denied -> assertThat(denied.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name()));
            verify(methodInvocation, never()).proceed();
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("SHADOW mode: a stored CHALLENGE is observed and the asynchronous method runs")
        void shadow_storedChallengeIsNotEnforced() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("result");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(shadow);
            when(synchronousProtectableDecisionService.asyncGate(methodInvocation, authentication))
                    .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.restricted(ZeroTrustAction.CHALLENGE));

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");
            verify(methodInvocation).proceed();
        }

        @Test
        @DisplayName("ENFORCE mode: without a stored restriction the asynchronous method runs")
        void enforce_noStoredRestrictionRuns() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("result");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);
            when(synchronousProtectableDecisionService.asyncGate(methodInvocation, authentication))
                    .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");
            verify(methodInvocation).proceed();
        }
    }

    @Nested
    @DisplayName("RL-12: an agent's request that passes before its verdict, and one the analysis cannot take in")
    class AgentRequestsInNumbersTests {

        private void enforceWith(SynchronousProtectableDecisionService.AsyncProtectableGate gate,
                                 SecurityZeroTrustProperties.EnforcementMode mode) {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
            SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
            properties.setMode(mode);
            interceptor.setSecurityZeroTrustProperties(properties);
            when(synchronousProtectableDecisionService.asyncGate(methodInvocation, authentication)).thenReturn(gate);
        }

        @Test
        @DisplayName("the first request that passes runs, and its event is published: it is the analysis that decides")
        void thePassThatLeadsRunsAndPublishesItsEvent() throws Throwable {
            when(methodInvocation.proceed()).thenReturn("result");
            enforceWith(SynchronousProtectableDecisionService.AsyncProtectableGate.PASS_AND_ANALYSE,
                    SecurityZeroTrustProperties.EnforcementMode.ENFORCE);

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");

            verify(methodInvocation).proceed();
            verify(synchronousProtectableDecisionService, never()).analyze(any(MethodInvocation.class), any());
            verify(zeroTrustEventPublisher).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("a request that passes while a verdict is pending runs and publishes nothing: it is only recorded")
        void aPassThatFollowsRunsAndPublishesNothing() throws Throwable {
            when(methodInvocation.proceed()).thenReturn("result");
            enforceWith(SynchronousProtectableDecisionService.AsyncProtectableGate.PASS_AND_RECORD,
                    SecurityZeroTrustProperties.EnforcementMode.ENFORCE);

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");

            verify(methodInvocation).proceed();
            verify(synchronousProtectableDecisionService, never()).analyze(any(MethodInvocation.class), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("a request the analysis has no place for is refused with 429 and never runs")
        void aBusyAnalysisRefusesTheRequestAndTheMethodNeverRuns() throws Throwable {
            enforceWith(SynchronousProtectableDecisionService.AsyncProtectableGate.DECIDE_IN_PLACE,
                    SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenThrow(ZeroTrustAccessDeniedException.analysisBusy("ContexaBusinessOperations#readDocument", 10));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class, denied -> {
                        assertThat(denied.getHttpStatus()).isEqualTo(429);
                        assertThat(denied.getBusyRetryAfterSeconds()).isEqualTo(10);
                    });
            verify(methodInvocation, never()).proceed();
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("A1-5: an agent request with no decision on record at an asynchronous Protectable")
    class UnrecordedAgentRequestTests {

        private void enforceWithGate(SecurityZeroTrustProperties.EnforcementMode mode) {
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
            SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
            properties.setMode(mode);
            interceptor.setSecurityZeroTrustProperties(properties);
            when(synchronousProtectableDecisionService.asyncGate(methodInvocation, authentication))
                    .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.DECIDE_IN_PLACE);
        }

        private void decided(ZeroTrustAction action) {
            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenReturn(new SynchronousProtectableDecisionService.SyncDecisionResult(null, null, action, null, null));
        }

        @Test
        @DisplayName("an ALLOW decided in place lets the method run")
        void decidedAllowRuns() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("result");
            enforceWithGate(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            decided(ZeroTrustAction.ALLOW);

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");
            verify(synchronousProtectableDecisionService).analyze(methodInvocation, authentication);
            // The decision was made in the request; no second analysis is queued for it.
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("a BLOCK decided in place stops the method")
        void decidedBlockStops() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            enforceWithGate(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            decided(ZeroTrustAction.BLOCK);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                            denied -> assertThat(denied.getHttpStatus()).isEqualTo(403));
            verify(methodInvocation, never()).proceed();
        }

        @Test
        @DisplayName("when the model is unavailable the technical fallback (ESCALATE) answers with 423, never a pass")
        void technicalFallbackAnswersWithLocked() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            enforceWithGate(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            decided(ZeroTrustAction.ESCALATE);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class, denied -> {
                        assertThat(denied.getAction()).isEqualTo(ZeroTrustAction.ESCALATE.name());
                        assertThat(denied.getHttpStatus()).isEqualTo(423);
                    });
            verify(methodInvocation, never()).proceed();
        }

        @Test
        @DisplayName("an analysis that leaves no decision answers that analysis is required (503), never a pass")
        void noDecisionAnswersAnalysisRequired() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            enforceWithGate(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            decided(ZeroTrustAction.PENDING_ANALYSIS);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                            denied -> assertThat(denied.getHttpStatus()).isEqualTo(503));
            verify(methodInvocation, never()).proceed();
        }

        @Test
        @DisplayName("a request while the session's analysis is in progress waits instead of running undecided")
        void rapidReentryWaits() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(false);
            enforceWithGate(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                            denied -> assertThat(denied.getAction()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name()));
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(methodInvocation, never()).proceed();
        }

        @Test
        @DisplayName("SHADOW mode: the decision in place is observed and the method runs")
        void shadowObservesAndRuns() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("result");
            enforceWithGate(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            decided(ZeroTrustAction.BLOCK);

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");
            verify(synchronousProtectableDecisionService).analyze(methodInvocation, authentication);
        }

        @Test
        @DisplayName("a person's request (the gate says proceed) runs without a decision in place, as before")
        void personsRequestProceeds() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("result");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);
            when(synchronousProtectableDecisionService.asyncGate(methodInvocation, authentication))
                    .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);

            assertThat(interceptor.invoke(methodInvocation)).isEqualTo("result");
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
        }
    }

    @Nested
    @DisplayName("Authorization result and execution outcome (W1-6)")
    class AuthorizationResultTests {

        @Test
        @DisplayName("a business exception after the method ran is an execution failure, not a denial")
        void businessExceptionIsAnExecutionFailure() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);
            when(methodInvocation.proceed()).thenThrow(new IllegalArgumentException("document not found"));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(IllegalArgumentException.class);

            verify(zeroTrustEventPublisher).publishMethodAuthorization(
                    eq(methodInvocation), eq(authentication), eq(true), isNull(),
                    eq(ZeroTrustEventPublisher.METHOD_FAILED), eq("IllegalArgumentException"));
        }

        @Test
        @DisplayName("a real policy denial is recorded for the session and the scope, without analysis")
        void policyDenialIsRecorded() throws Throwable {
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);
            interceptor.setAuthorizationDenialRecorder(authorizationDenialRecorder);
            doThrow(new AuthorizationDeniedException("role cannot read customers"))
                    .when(authorizationManager).protectable(any(), eq(methodInvocation));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(AuthorizationDeniedException.class);

            verify(authorizationDenialRecorder).record(methodInvocation, authentication, "role cannot read customers");
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
            verify(methodInvocation, never()).proceed();
        }
    }

    static class SampleService {
        public String sampleMethod() {
            return "result";
        }
    }

    static class SyncProtectableService {
        @Protectable(sync = true)
        public String protectedMethod() {
            return "protected";
        }
    }

    @Nested
    @DisplayName("Shadow mode sync Protectable handling")
    class ShadowModeSyncTests {

        @Test
        @DisplayName("DISABLED mode: sync Protectable should skip AI analysis and proceed")
        void disabled_syncProtectable_shouldSkipAiAnalysisAndProceed() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties disabled = new SecurityZeroTrustProperties();
            disabled.setMode(SecurityZeroTrustProperties.EnforcementMode.DISABLED);
            interceptor.setSecurityZeroTrustProperties(disabled);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
            verify(rapidReentryGuard, never()).tryAcquire(any(), any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("OBSERVE mode: sync Protectable should observe authorization only and skip AI analysis")
        void observe_syncProtectable_shouldSkipAiAnalysisAndProceed() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties observe = new SecurityZeroTrustProperties();
            observe.setMode(SecurityZeroTrustProperties.EnforcementMode.OBSERVE);
            interceptor.setSecurityZeroTrustProperties(observe);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
            verify(rapidReentryGuard, never()).tryAcquire(any(), any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("ENFORCE mode: sync BLOCK should throw ZeroTrustAccessDeniedException")
        void enforce_syncBlock_shouldThrow() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);

            SynchronousProtectableDecisionService.SyncDecisionResult blockResult =
                    new SynchronousProtectableDecisionService.SyncDecisionResult(
                            null, null, ZeroTrustAction.BLOCK, null, null);
            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenReturn(blockResult);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(ZeroTrustAccessDeniedException.class);

            verify(methodInvocation, never()).proceed();
        }

        @Test
        @DisplayName("SHADOW mode: sync BLOCK should NOT throw and should proceed")
        void shadow_syncBlock_shouldProceed() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(shadow);

            SynchronousProtectableDecisionService.SyncDecisionResult blockResult =
                    new SynchronousProtectableDecisionService.SyncDecisionResult(
                            null, null, ZeroTrustAction.BLOCK, null, null);
            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenReturn(blockResult);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(methodInvocation).proceed();
        }

        @Test
        @DisplayName("SHADOW mode: sync ALLOW should proceed normally (no behavior change)")
        void shadow_syncAllow_shouldProceedSame() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(shadow);

            SynchronousProtectableDecisionService.SyncDecisionResult allowResult =
                    new SynchronousProtectableDecisionService.SyncDecisionResult(
                            null, null, ZeroTrustAction.ALLOW, null, null);
            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenReturn(allowResult);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(methodInvocation).proceed();
        }

        @Test
        @DisplayName("SHADOW mode: sync evaluation failure should be recorded and access should proceed")
        void shadow_syncEvaluationFailure_shouldProceed() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(shadow);

            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenThrow(new IllegalStateException("Security event pipeline did not produce a final result"));

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(synchronousProtectableDecisionService).analyze(methodInvocation, authentication);
            verify(methodInvocation).proceed();
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("ENFORCE mode: sync evaluation failure should still fail closed")
        void enforce_syncEvaluationFailure_shouldThrow() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);

            when(synchronousProtectableDecisionService.analyze(methodInvocation, authentication))
                    .thenThrow(new IllegalStateException("Security event pipeline did not produce a final result"));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Security event pipeline did not produce a final result");

            verify(synchronousProtectableDecisionService).analyze(methodInvocation, authentication);
            verify(methodInvocation, never()).proceed();
        }

        @Test
        @DisplayName("SHADOW mode: missing sync decision service should be recorded and access should proceed")
        void shadow_missingSyncDecisionService_shouldProceed() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("protected");

            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(shadow);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(methodInvocation).proceed();
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any(), any(), any());
        }

        @Test
        @DisplayName("ENFORCE mode: missing sync decision service should still require analysis")
        void enforce_missingSyncDecisionService_shouldRequireAnalysis() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(eq(authentication), eq(methodInvocation), anyString())).thenReturn(true);

            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            interceptor.setSecurityZeroTrustProperties(enforce);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class, denied -> {
                        assertThat(denied.getAction()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name());
                        assertThat(denied.getResourceId()).isEqualTo("SyncProtectableService.protectedMethod");
                    });

            verify(methodInvocation, never()).proceed();
        }
    }
}
