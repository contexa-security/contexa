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
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** PR-42: a failed single-factor sign-in says nothing about the account, as the MFA flow does not. */
class SessionSingleAuthFailureHandlerTest {

    private static Stream<AuthenticationException> everyWayASignInFails() {
        return Stream.of(
                new UsernameNotFoundException("User not found: ghost"),
                new BadCredentialsException("Invalid password"),
                new BadCredentialsException("External authentication only account"),
                new LockedException("Account is locked"),
                new DisabledException("Account is disabled"),
                new AccountExpiredException("Account has expired"));
    }

    @ParameterizedTest
    @MethodSource("everyWayASignInFails")
    @DisplayName("Every failed sign-in is answered with the same code and the same words")
    void everyFailureGetsTheSameAnswer(AuthenticationException failure) throws Exception {
        assertThat(answerTo(failure)).isEqualTo(List.of("PRIMARY_AUTH_FAILED", "Invalid username or password.",
                "PRIMARY_AUTH_FAILED", "Invalid username or password."));
    }

    @Test
    @DisplayName("An expired password, told only after the password was right, still leads to the password change")
    void anExpiredPasswordStillLeadsToThePasswordChange() throws Exception {
        AuthResponseWriter writer = mock(AuthResponseWriter.class);
        SessionSingleAuthFailureHandler handler =
                new SessionSingleAuthFailureHandler(writer, new AuthContextProperties(), null);

        handler.onAuthenticationFailure(apiRequest(), new MockHttpServletResponse(),
                new CredentialsExpiredException("Password has expired"));

        verify(writer).writeErrorResponse(any(), eq(401), eq("CREDENTIALS_EXPIRED"), eq("Password has expired"), any(),
                any());
        verify(writer, never()).writeErrorResponse(any(), anyInt(), eq("PRIMARY_AUTH_FAILED"), anyString(), any(), any());
    }

    @SuppressWarnings("unchecked")
    private static List<String> answerTo(AuthenticationException failure) throws Exception {
        AuthResponseWriter writer = mock(AuthResponseWriter.class);
        SessionSingleAuthFailureHandler handler =
                new SessionSingleAuthFailureHandler(writer, new AuthContextProperties(), null);

        handler.onAuthenticationFailure(apiRequest(), new MockHttpServletResponse(), failure);

        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(writer).writeErrorResponse(any(), eq(401), code.capture(), message.capture(), any(), details.capture());
        return List.of(code.getValue(), message.getValue(),
                details.getValue().get("errorCode").toString(), details.getValue().get("message").toString());
    }

    private static MockHttpServletRequest apiRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login");
        request.addHeader("Accept", "application/json");
        return request;
    }
}
