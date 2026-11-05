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
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CF-01: the success and failure handlers an application sets on a single-factor flow in the OAuth2 state run, under
 * the rule of the MFA handlers: the application's handler gets the result first (the tokens on success) and Contexa
 * writes its own response only when that handler wrote none.
 */
class OAuth2SingleAuthHandlersDelegateTest {

    private final TokenService tokenService = mock(TokenService.class);
    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final Authentication alice = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    @Test
    void theApplicationsSuccessHandlerGetsTheTokensAndItsResponseStands() throws Exception {
        OAuth2SingleAuthSuccessHandler handler = successHandler();
        PlatformAuthenticationSuccessHandler application = mock(PlatformAuthenticationSuccessHandler.class);
        doAnswer(invocation -> {
            MockHttpServletResponse response = invocation.getArgument(1);
            response.setStatus(202);
            response.getWriter().write("application response");
            response.flushBuffer();
            return null;
        }).when(application).onAuthenticationSuccess(any(), any(), any(), any(TokenTransportResult.class));
        handler.setDelegateHandler(application);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(jsonRequest(), response, alice);

        ArgumentCaptor<TokenTransportResult> result = ArgumentCaptor.forClass(TokenTransportResult.class);
        verify(application).onAuthenticationSuccess(any(), any(), eq(alice), result.capture());
        assertThat(result.getValue().getBody()).containsEntry("accessToken", "access-1")
                .containsEntry("authenticated", true);
        assertThat(response.getStatus()).isEqualTo(202);
        assertThat(response.getContentAsString()).isEqualTo("application response");
        verify(responseWriter, never()).writeSuccessResponse(any(), any(), anyInt());
    }

    @Test
    void contexaWritesItsResponseWhenTheApplicationsSuccessHandlerWroteNone() throws Exception {
        OAuth2SingleAuthSuccessHandler handler = successHandler();
        PlatformAuthenticationSuccessHandler application = mock(PlatformAuthenticationSuccessHandler.class);
        handler.setDelegateHandler(application);

        handler.onAuthenticationSuccess(jsonRequest(), new MockHttpServletResponse(), alice);

        verify(application).onAuthenticationSuccess(any(), any(), eq(alice), any(TokenTransportResult.class));
        verify(responseWriter).writeSuccessResponse(any(), anyMap(), eq(200));
    }

    @Test
    void withoutAnApplicationHandlerTheSuccessResponseIsContexas() throws Exception {
        successHandler().onAuthenticationSuccess(jsonRequest(), new MockHttpServletResponse(), alice);

        ArgumentCaptor<Map<String, Object>> body = ArgumentCaptor.forClass(Map.class);
        verify(responseWriter).writeSuccessResponse(any(), body.capture(), eq(200));
        assertThat(body.getValue()).containsEntry("accessToken", "access-1").containsEntry("username", "alice");
    }

    @Test
    void theApplicationsFailureHandlerRunsAndItsResponseStands() throws Exception {
        OAuth2SingleAuthFailureHandler handler = new OAuth2SingleAuthFailureHandler(responseWriter, null);
        PlatformAuthenticationFailureHandler application = mock(PlatformAuthenticationFailureHandler.class);
        doAnswer(invocation -> {
            MockHttpServletResponse response = invocation.getArgument(1);
            response.setStatus(429);
            response.flushBuffer();
            return null;
        }).when(application).onAuthenticationFailure(any(), any(), any(), any(), any(), any());
        handler.setDelegateHandler(application);
        MockHttpServletResponse response = new MockHttpServletResponse();
        BadCredentialsException failure = new BadCredentialsException("Bad credentials");

        handler.onAuthenticationFailure(jsonRequest(), response, failure);

        verify(application).onAuthenticationFailure(any(), any(), eq(failure), isNull(),
                eq(PlatformAuthenticationFailureHandler.FailureType.PRIMARY_AUTH_FAILED), anyMap());
        assertThat(response.getStatus()).isEqualTo(429);
        verify(responseWriter, never()).writeErrorResponse(any(), anyInt(), anyString(), anyString(), any(), any());
    }

    @Test
    void contexaWritesTheFailureWhenTheApplicationsHandlerWroteNoneOrThereIsNone() throws Exception {
        OAuth2SingleAuthFailureHandler handler = new OAuth2SingleAuthFailureHandler(responseWriter, null);
        handler.setDelegateHandler(mock(PlatformAuthenticationFailureHandler.class));
        handler.onAuthenticationFailure(jsonRequest(), new MockHttpServletResponse(),
                new BadCredentialsException("Bad credentials"));
        new OAuth2SingleAuthFailureHandler(responseWriter, null).onAuthenticationFailure(jsonRequest(),
                new MockHttpServletResponse(), new BadCredentialsException("Bad credentials"));

        verify(responseWriter, times(2)).writeErrorResponse(any(), eq(401), anyString(),
                anyString(), any(), any());
    }

    @Test
    void anUnknownUserAWrongPasswordAndALockedAccountGetTheSameAnswer() throws Exception {
        OAuth2SingleAuthFailureHandler handler = new OAuth2SingleAuthFailureHandler(responseWriter, null);

        handler.onAuthenticationFailure(jsonRequest(), new MockHttpServletResponse(),
                new UsernameNotFoundException("User not found: ghost"));
        handler.onAuthenticationFailure(jsonRequest(), new MockHttpServletResponse(),
                new BadCredentialsException("Invalid password"));
        handler.onAuthenticationFailure(jsonRequest(), new MockHttpServletResponse(),
                new LockedException("Account is locked"));

        verify(responseWriter, times(3)).writeErrorResponse(any(), eq(401), eq("AUTHENTICATION_FAILED"),
                eq("Invalid username or password."), any(), any());
    }

    private OAuth2SingleAuthSuccessHandler successHandler() {
        when(tokenService.createTokenPair(any(), isNull(), any(), any()))
                .thenReturn(TokenPair.builder().accessToken("access-1").refreshToken("refresh-1").build());
        when(tokenService.prepareTokensForTransport("access-1", "refresh-1"))
                .thenReturn(TokenTransportResult.builder().body(Map.of("accessToken", "access-1")).build());
        return new OAuth2SingleAuthSuccessHandler(tokenService, responseWriter, new AuthContextProperties(), null);
    }

    private static MockHttpServletRequest jsonRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login");
        request.addHeader("Accept", "application/json");
        return request;
    }
}
