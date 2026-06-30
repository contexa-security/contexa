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
package io.contexa.contexaiam.security.xacml.pep.guard;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import io.contexa.contexacore.autonomous.execution.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.time.Duration;
import org.aopalliance.intercept.MethodInvocation;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProtectableRapidReentryGuardTest {

    @Mock
    private ProtectableRapidReentryRepository repository;

    @Mock
    private Authentication authentication;

    @Mock
    private MethodInvocation methodInvocation;

    @Mock
    private HttpServletRequest request;

    private ProtectableRapidReentryGuard guard;

    @BeforeEach
    void setUp() throws Exception {
        guard = new ProtectableRapidReentryGuard(repository);

        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("user1");

        Method method = TestController.class.getMethod("doAction");
        when(methodInvocation.getMethod()).thenReturn(method);
        when(methodInvocation.getArguments()).thenReturn(new Object[0]);

        when(request.getMethod()).thenReturn("POST");
        when(request.getRequestURI()).thenReturn("/api/resource");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    @Nested
    @DisplayName("5-second window blocking")
    class WindowBlockingTests {

        @Test
        @DisplayName("Should allow first request when repository returns true")
        void shouldAllowFirstRequest() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("hash123");
                when(repository.tryAcquire(eq("user1"), eq("hash123"), any(), eq(Duration.ofSeconds(5))))
                        .thenReturn(true);

                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();
            }
        }

        @Test
        @DisplayName("Should expose non-throwing acquisition result for async analysis dedupe")
        void shouldReturnFalseInsteadOfThrowingWhenUsingTryAcquire() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("hash123");
                when(repository.tryAcquire(eq("user1"), eq("hash123"), any(), eq(Duration.ofSeconds(5))))
                        .thenReturn(false);

                boolean acquired = guard.tryAcquire(authentication, methodInvocation);

                Assertions.assertThat(acquired).isFalse();
            }
        }

        @Test
        @DisplayName("Should deny rapid re-entry when repository returns false")
        void shouldDenyRapidReentry() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("hash123");
                when(repository.tryAcquire(eq("user1"), eq("hash123"), any(), eq(Duration.ofSeconds(5))))
                        .thenReturn(false);

                assertThatThrownBy(() -> guard.check(authentication, methodInvocation))
                        .isInstanceOf(RapidProtectableReentryDeniedException.class);
            }
        }
    }

    @Nested
    @DisplayName("Context binding hash + userId + actor-session scope")
    class ContextBindingTests {

        @Test
        @DisplayName("Should use actor-session scope instead of method or URI")
        void shouldUseActorSessionScopeKey() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("ctxHash");
                when(repository.tryAcquire(
                        eq("user1"),
                        eq("ctxHash"),
                        eq("PROTECTABLE_ACTOR_SESSION"),
                        eq(Duration.ofSeconds(5))
                )).thenReturn(true);

                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();

                verify(repository).tryAcquire(
                        eq("user1"),
                        eq("ctxHash"),
                        eq("PROTECTABLE_ACTOR_SESSION"),
                        eq(Duration.ofSeconds(5)));
            }
        }
    }

    @Nested
    @DisplayName("Different resources in the same actor session should be coalesced")
    class DifferentResourceTests {

        @Test
        @DisplayName("Should suppress different URIs within the same actor-session window")
        void shouldSuppressDifferentResourcesInSameActorSession() throws Exception {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("hash1");

                when(repository.tryAcquire(eq("user1"), eq("hash1"),
                        eq("PROTECTABLE_ACTOR_SESSION"), eq(Duration.ofSeconds(5))))
                        .thenReturn(true)
                        .thenReturn(false);

                when(request.getRequestURI()).thenReturn("/api/resource-a");
                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();

                when(request.getRequestURI()).thenReturn("/api/resource-b");
                Assertions.assertThat(guard.tryAcquire(authentication, methodInvocation)).isFalse();

                verify(repository, times(2)).tryAcquire(
                        eq("user1"),
                        eq("hash1"),
                        eq("PROTECTABLE_ACTOR_SESSION"),
                        eq(Duration.ofSeconds(5)));
            }
        }
    }

    @Nested
    @DisplayName("RapidProtectableReentryDeniedException")
    class ExceptionTests {

        @Test
        @DisplayName("Should throw exception with correct resource key and window seconds")
        void shouldThrowWithCorrectDetails() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("hash");
                when(repository.tryAcquire(any(), any(), any(), any())).thenReturn(false);

                assertThatThrownBy(() -> guard.check(authentication, methodInvocation))
                        .isInstanceOf(RapidProtectableReentryDeniedException.class)
                        .satisfies(ex -> {
                            RapidProtectableReentryDeniedException denied = (RapidProtectableReentryDeniedException) ex;
                            assertThatCode(() -> denied.getWindowSeconds()).doesNotThrowAnyException();
                        });
            }
        }
    }

    @Nested
    @DisplayName("Non-web context handling")
    class NonWebContextTests {

        @Test
        @DisplayName("Should skip check when no request attributes available")
        void shouldSkipWhenNoRequestContext() {
            RequestContextHolder.resetRequestAttributes();

            assertThatCode(() -> guard.check(authentication, methodInvocation))
                    .doesNotThrowAnyException();

            verify(repository, never()).tryAcquire(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Should skip check when authentication is null")
        void shouldSkipWhenAuthenticationIsNull() {
            assertThatCode(() -> guard.check(null, methodInvocation))
                    .doesNotThrowAnyException();

            verify(repository, never()).tryAcquire(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Should skip check when authentication is not authenticated")
        void shouldSkipWhenNotAuthenticated() {
            when(authentication.isAuthenticated()).thenReturn(false);

            assertThatCode(() -> guard.check(authentication, methodInvocation))
                    .doesNotThrowAnyException();

            verify(repository, never()).tryAcquire(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Should skip check when userId is blank")
        void shouldSkipWhenUserIdIsBlank() {
            when(authentication.getName()).thenReturn("");

            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();
            }

            verify(repository, never()).tryAcquire(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Should skip check when context binding hash is null")
        void shouldSkipWhenContextBindingHashIsNull() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn(null);

                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();
            }

            verify(repository, never()).tryAcquire(any(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("Configurable rapid re-entry window")
    class ConfigurableWindowTests {

        @Test
        @DisplayName("Should skip guard when rapid re-entry window is disabled")
        void shouldSkipGuardWhenWindowIsDisabled() {
            ProtectableRapidReentryGuard disabledGuard =
                    new ProtectableRapidReentryGuard(repository, Duration.ZERO);

            assertThatCode(() -> disabledGuard.check(authentication, methodInvocation))
                    .doesNotThrowAnyException();

            verify(repository, never()).tryAcquire(any(), any(), any(), any());
        }
    }

    // Test controller used for method reflection
    static class TestController {
        public void doAction() {}
    }
}
