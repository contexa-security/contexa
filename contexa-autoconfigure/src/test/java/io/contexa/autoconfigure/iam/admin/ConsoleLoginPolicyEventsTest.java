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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaiam.security.core.LoginAttemptIpUpserter;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.springframework.beans.factory.ObjectProvider;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Exception test E-B7 (2026-11-03): twelve wrong passwords for the administrator at the HOST_OWNED console were all
 * answered the same way and the right one still signed in. The console chain's authentication manager had no event
 * publisher, and Contexa's login policy listens to those events only when Contexa owns sign-in (so that the
 * application's own sign-ins never count against Contexa's accounts). The console feeds the policy itself.
 */
class ConsoleLoginPolicyEventsTest {

    private final LoginPolicyHandler handler = mock(LoginPolicyHandler.class);
    private final Authentication attempt = new UsernamePasswordAuthenticationToken("admin", "secret");

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    private ConsoleLoginPolicyEvents events(LoginPolicyHandler... handlers) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        for (LoginPolicyHandler each : handlers) {
            beans.addBean("handler", each);
        }
        return new ConsoleLoginPolicyEvents(beans.getBeanProvider(LoginPolicyHandler.class));
    }

    @Test
    @DisplayName("a failed console sign-in is counted against the account, with the address it came from")
    void aFailureIsCounted() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login");
        request.setRemoteAddr("203.0.113.7");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        events(handler).publishAuthenticationFailure(new BadCredentialsException("bad"), attempt);

        verify(handler).onLoginFailure("admin", "203.0.113.7", "BadCredentialsException", "CONSOLE");
    }

    /** PR-69: the console's count is no better than its address. */
    @Test
    @DisplayName("a forged forwarded header does not change the address a failed console sign-in counts against")
    void aForgedHeaderDoesNotChangeTheAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login");
        request.setRemoteAddr("203.0.113.7");
        request.addHeader("X-Forwarded-For", "198.51.100.77");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        events(handler).publishAuthenticationFailure(new BadCredentialsException("bad"), attempt);

        verify(handler).onLoginFailure("admin", "203.0.113.7", "BadCredentialsException", "CONSOLE");
    }

    @Test
    @DisplayName("a locked account's attempt is counted too, and a success resets the account")
    void lockedAttemptsCountAndSuccessResets() {
        ConsoleLoginPolicyEvents events = events(handler);

        events.publishAuthenticationFailure(new LockedException("locked"), attempt);
        events.publishAuthenticationSuccess(attempt);

        verify(handler).onLoginFailure(eq("admin"), any(), eq("LockedException"), eq("CONSOLE"));
        verify(handler).onLoginSuccess(eq("admin"), any(), eq("CONSOLE"));
    }

    @Test
    @DisplayName("the policy failing, or no policy at all, never turns into a failed sign-in")
    void theConsoleNeverFailsBecauseOfThePolicy() {
        doThrow(new IllegalStateException("database down")).when(handler).onLoginFailure(anyString(), any(), anyString(),
                anyString());

        assertThatCode(() -> events(handler).publishAuthenticationFailure(new BadCredentialsException("bad"), attempt))
                .doesNotThrowAnyException();
        assertThatCode(() -> events().publishAuthenticationFailure(new BadCredentialsException("bad"), attempt))
                .doesNotThrowAnyException();
        assertThatCode(() -> events().publishAuthenticationSuccess(attempt)).doesNotThrowAnyException();
    }

    /**
     * The policy keeps a marker per thread so that one failure is counted once; it is cleared at the end of each
     * request by a filter that exists only when Contexa owns sign-in. Without clearing it here, the second failure on
     * a recycled worker thread would not be counted and the lock would never come.
     */
    @Test
    @DisplayName("two failures on one thread are both counted (the policy's per-thread marker is cleared)")
    void everyFailureOnAThreadIsCounted() {
        UserRepository users = mock(UserRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<SecurityContextDataStore> store = mock(ObjectProvider.class);
        LoginPolicyService policy = new LoginPolicyService(users, mock(LoginAttemptIpRepository.class),
                mock(PasswordPolicyService.class), mock(LoginAttemptIpUpserter.class), store);
        ConsoleLoginPolicyEvents events = events(policy);

        events.publishAuthenticationFailure(new BadCredentialsException("1"), attempt);
        events.publishAuthenticationFailure(new BadCredentialsException("2"), attempt);
        events.publishAuthenticationFailure(new BadCredentialsException("3"), attempt);

        verify(users, times(3)).incrementFailedAttempts("admin");
    }
}
