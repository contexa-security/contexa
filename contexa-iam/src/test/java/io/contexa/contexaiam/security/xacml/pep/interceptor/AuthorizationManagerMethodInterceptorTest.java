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
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("success");

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("success");
            verify(rapidReentryGuard).tryAcquire(authentication, methodInvocation);
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
        }

        @Test
        @DisplayName("Should publish authorization event on successful invocation")
        void shouldPublishEventOnSuccess() throws Throwable {
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("ok");

            interceptor.invoke(methodInvocation);

            verify(zeroTrustEventPublisher).publishMethodAuthorization(
                    eq(methodInvocation), eq(authentication), eq(true), isNull());
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
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(false);
            when(methodInvocation.proceed()).thenReturn("success");

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("success");
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
            verify(rapidReentryGuard, never()).check(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any());
        }

        @Test
        @DisplayName("ENFORCE should not create another sync LLM decision on actor-session rapid re-entry")
        void enforceSyncProtectableShouldRejectWithoutDuplicateLlmOnRapidReentry() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(false);

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(ZeroTrustAccessDeniedException.class);

            verify(rapidReentryGuard, never()).check(any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any());
        }

        @Test
        @DisplayName("SHADOW should proceed and skip duplicate sync LLM decision on actor-session rapid re-entry")
        void shadowSyncProtectableShouldProceedWithoutDuplicateLlmOnRapidReentry() throws Throwable {
            SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
            properties.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
            interceptor.setSecurityZeroTrustProperties(properties);
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(false);
            when(methodInvocation.proceed()).thenReturn("success");

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("success");
            verify(rapidReentryGuard, never()).check(any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any());
        }
    }

    @Nested
    @DisplayName("Deny handling")
    class DenyHandlingTests {

        @Test
        @DisplayName("Should handle AuthorizationDeniedException via handler and publish event")
        void shouldHandleAuthorizationDenied() throws Throwable {
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
            AuthorizationDeniedException denied = new AuthorizationDeniedException("denied");
            doThrow(denied).when(authorizationManager).protectable(any(), eq(methodInvocation));

            // Default handler rethrows
            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(AuthorizationDeniedException.class);

            verify(zeroTrustEventPublisher).publishMethodAuthorization(
                    eq(methodInvocation), eq(authentication), eq(false), eq("denied"));
        }

        @Test
        @DisplayName("Should not publish event for ZeroTrustAccessDeniedException")
        void shouldNotPublishEventForZeroTrustDenied() throws Throwable {
            ZeroTrustAccessDeniedException ztDenied =
                    ZeroTrustAccessDeniedException.blocked("SampleService.sampleMethod");
            doThrow(ztDenied).when(authorizationManager).protectable(any(), eq(methodInvocation));

            assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                    .isInstanceOf(ZeroTrustAccessDeniedException.class);

            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any());
        }
    }

    @Nested
    @DisplayName("Event publishing with metrics")
    class EventPublishingTests {

        @Test
        @DisplayName("Should record metrics when event is published")
        void shouldRecordMetrics() throws Throwable {
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
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
            disabled.setMode(SecurityZeroTrustProperties.SecurityMode.DISABLED);
            interceptor.setSecurityZeroTrustProperties(disabled);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
            verify(rapidReentryGuard, never()).tryAcquire(any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any());
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
            observe.setMode(SecurityZeroTrustProperties.SecurityMode.OBSERVE);
            interceptor.setSecurityZeroTrustProperties(observe);

            Object result = interceptor.invoke(methodInvocation);

            assertThat(result).isEqualTo("protected");
            verify(authorizationManager).protectable(any(), eq(methodInvocation));
            verify(rapidReentryGuard, never()).tryAcquire(any(), any());
            verify(synchronousProtectableDecisionService, never()).analyze(any(), any());
            verify(zeroTrustEventPublisher, never()).publishMethodAuthorization(any(), any(), anyBoolean(), any());
        }

        @Test
        @DisplayName("ENFORCE mode: sync BLOCK should throw ZeroTrustAccessDeniedException")
        void enforce_syncBlock_shouldThrow() throws Throwable {
            Method method = SyncProtectableService.class.getMethod("protectedMethod");
            when(methodInvocation.getMethod()).thenReturn(method);
            when(methodInvocation.getThis()).thenReturn(new SyncProtectableService());
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties enforce = new SecurityZeroTrustProperties();
            enforce.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
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
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
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
            when(rapidReentryGuard.tryAcquire(authentication, methodInvocation)).thenReturn(true);
            when(methodInvocation.proceed()).thenReturn("protected");
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);

            SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
            shadow.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
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
    }
}
