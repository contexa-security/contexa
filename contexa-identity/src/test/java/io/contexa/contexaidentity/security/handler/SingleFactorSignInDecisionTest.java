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
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Where Contexa owns the sign-in, a single-factor login its own handlers complete (a REST login on the session state,
 * any login on the token state) goes to the engine before the response leaves.
 */
class SingleFactorSignInDecisionTest {

    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final Authentication alice = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    private static MockHttpServletRequest jsonRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login");
        request.addHeader("Accept", "application/json");
        return request;
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> facts() {
        return ArgumentCaptor.forClass(Map.class);
    }

    private OAuth2SingleAuthSuccessHandler tokenHandler() {
        TokenService tokenService = mock(TokenService.class);
        when(tokenService.createTokenPair(any(), isNull(), any(), any()))
                .thenReturn(TokenPair.builder().accessToken("access-1").refreshToken("refresh-1").build());
        when(tokenService.prepareTokensForTransport("access-1", "refresh-1"))
                .thenReturn(TokenTransportResult.builder().body(Map.of("accessToken", "access-1")).build());
        OAuth2SingleAuthSuccessHandler handler =
                new OAuth2SingleAuthSuccessHandler(tokenService, responseWriter, new AuthContextProperties(), null);
        handler.setZeroTrustEventPublisher(publisher);
        return handler;
    }

    private SessionSingleAuthSuccessHandler sessionHandler() {
        SessionSingleAuthSuccessHandler handler =
                new SessionSingleAuthSuccessHandler(responseWriter, new AuthContextProperties(), null);
        handler.setZeroTrustEventPublisher(publisher);
        return handler;
    }

    @Test
    @DisplayName("a single-factor login on the session state goes to the engine")
    void aSessionLoginIsDecided() throws Exception {
        MockHttpServletRequest request = jsonRequest();

        sessionHandler().onAuthenticationSuccess(request, new MockHttpServletResponse(), alice);

        ArgumentCaptor<Map<String, Object>> facts = facts();
        verify(publisher).publishAuthenticationSuccess(eq(alice), eq(request), facts.capture());
        assertThat(facts.getValue()).containsEntry("authenticationType", "SINGLE");
    }

    @Test
    @DisplayName("a single-factor login on the token state goes to the engine")
    void aTokenLoginIsDecided() throws Exception {
        MockHttpServletRequest request = jsonRequest();

        tokenHandler().onAuthenticationSuccess(request, new MockHttpServletResponse(), alice);

        ArgumentCaptor<Map<String, Object>> facts = facts();
        verify(publisher).publishAuthenticationSuccess(eq(alice), eq(request), facts.capture());
        assertThat(facts.getValue()).containsEntry("authenticationType", "SINGLE");
    }

    @Test
    @DisplayName("it goes before the response is written")
    void itGoesBeforeTheResponse() throws Exception {
        List<String> order = new ArrayList<>();
        doAnswer(call -> order.add("sign-in")).when(publisher).publishAuthenticationSuccess(any(), any(), any());
        doAnswer(call -> order.add("response")).when(responseWriter).writeSuccessResponse(any(), any(), eq(200));

        sessionHandler().onAuthenticationSuccess(jsonRequest(), new MockHttpServletResponse(), alice);
        tokenHandler().onAuthenticationSuccess(jsonRequest(), new MockHttpServletResponse(), alice);

        assertThat(order).containsExactly("sign-in", "response", "sign-in", "response");
    }

    @Test
    @DisplayName("an engine that cannot take the sign-in does not stop it")
    void anEngineThatFailsDoesNotStopIt() throws Exception {
        doThrow(new IllegalStateException("no engine")).when(publisher).publishAuthenticationSuccess(any(), any(), any());

        assertThatCode(() -> sessionHandler().onAuthenticationSuccess(jsonRequest(), new MockHttpServletResponse(), alice))
                .doesNotThrowAnyException();
        assertThatCode(() -> tokenHandler().onAuthenticationSuccess(jsonRequest(), new MockHttpServletResponse(), alice))
                .doesNotThrowAnyException();
        verify(responseWriter, times(2)).writeSuccessResponse(any(), any(), eq(200));
    }
}
