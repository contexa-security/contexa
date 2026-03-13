package io.contexa.contexaiam.security.xacml.pep.guard;

import io.contexa.contexacore.autonomous.exception.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

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
    @DisplayName("Context binding hash + userId + resourceKey")
    class ContextBindingTests {

        @Test
        @DisplayName("Should build resourceKey from method and request")
        void shouldBuildCorrectResourceKey() {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("ctxHash");
                when(repository.tryAcquire(
                        eq("user1"),
                        eq("ctxHash"),
                        eq("TestController.doAction|POST /api/resource"),
                        eq(Duration.ofSeconds(5))
                )).thenReturn(true);

                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();

                verify(repository).tryAcquire(
                        eq("user1"),
                        eq("ctxHash"),
                        eq("TestController.doAction|POST /api/resource"),
                        eq(Duration.ofSeconds(5)));
            }
        }
    }

    @Nested
    @DisplayName("Different resources should be allowed")
    class DifferentResourceTests {

        @Test
        @DisplayName("Should allow access to different URIs independently")
        void shouldAllowDifferentResources() throws Exception {
            try (MockedStatic<SessionFingerprintUtil> fingerprint = mockStatic(SessionFingerprintUtil.class)) {
                fingerprint.when(() -> SessionFingerprintUtil.generateContextBindingHash(request))
                        .thenReturn("hash1");

                // First resource allowed
                when(request.getRequestURI()).thenReturn("/api/resource-a");
                when(repository.tryAcquire(eq("user1"), eq("hash1"),
                        eq("TestController.doAction|POST /api/resource-a"), eq(Duration.ofSeconds(5))))
                        .thenReturn(true);

                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();

                // Second resource also allowed (different resourceKey)
                when(request.getRequestURI()).thenReturn("/api/resource-b");
                when(repository.tryAcquire(eq("user1"), eq("hash1"),
                        eq("TestController.doAction|POST /api/resource-b"), eq(Duration.ofSeconds(5))))
                        .thenReturn(true);

                assertThatCode(() -> guard.check(authentication, methodInvocation))
                        .doesNotThrowAnyException();
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

    // Test controller used for method reflection
    static class TestController {
        public void doAction() {}
    }
}
