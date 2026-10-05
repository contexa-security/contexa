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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.enums.TokenTransportType;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2TokenRefreshFilterTest {

    private TokenService tokenService;
    private AuthResponseWriter responseWriter;

    @BeforeEach
    void setUp() {
        tokenService = mock(TokenService.class);
        responseWriter = mock(AuthResponseWriter.class);
        when(tokenService.prepareTokensForTransport(anyString(), any())).thenReturn(TokenTransportResult.builder()
                .cookiesToSet(List.of(ResponseCookie.from("accessToken", "new-access").path("/").build()))
                .body(Map.of("tokenTransportMethod", "COOKIE"))
                .build());
        when(tokenService.prepareClearTokens()).thenReturn(TokenTransportResult.builder()
                .cookiesToRemove(List.of(ResponseCookie.from("accessToken", "").maxAge(0).path("/").build()))
                .build());
    }

    @Test
    @DisplayName("A valid refresh token yields new tokens in the transport format")
    void refreshesTokens() throws Exception {
        MockHttpServletRequest request = refreshRequest();
        when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
        when(tokenService.refresh("refresh")).thenReturn(new TokenService.RefreshResult("new-access", "new-refresh"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(TokenTransportType.COOKIE).doFilter(request, response, new MockFilterChain());

        assertThat(response.getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("accessToken=new-access"));
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> body = ArgumentCaptor.forClass((Class) Map.class);
        verify(responseWriter).writeSuccessResponse(eq(response), body.capture(), eq(200));
        assertThat(body.getValue()).containsEntry("refreshed", true).containsEntry("tokenTransportMethod", "COOKIE");
    }

    @Test
    @DisplayName("A zero trust challenge asks for the MFA challenge instead of renewing")
    void challengeRequiresMfa() throws Exception {
        MockHttpServletRequest request = refreshRequest();
        when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
        when(tokenService.refresh("refresh")).thenThrow(new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2TokenService.MFA_CHALLENGE_REQUIRED_ERROR)));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(TokenTransportType.COOKIE).doFilter(request, response, new MockFilterChain());

        verify(responseWriter).writeErrorResponse(eq(response), eq(401), eq("MFA_CHALLENGE_REQUIRED"), anyString(), anyString());
        verify(tokenService, never()).prepareClearTokens();
    }

    @Test
    @DisplayName("An invalid refresh token is refused with 401 and the token cookies are removed")
    void invalidTokenClearsCookies() throws Exception {
        MockHttpServletRequest request = refreshRequest();
        when(tokenService.resolveRefreshToken(request)).thenReturn("reused");
        when(tokenService.refresh("reused")).thenThrow(new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN)));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(TokenTransportType.COOKIE).doFilter(request, response, new MockFilterChain());

        verify(responseWriter).writeErrorResponse(eq(response), eq(401), eq("INVALID_REFRESH_TOKEN"), anyString(), anyString());
        assertThat(response.getHeaders("Set-Cookie")).allMatch(c -> c.contains("Max-Age=0"));
    }

    @Test
    @DisplayName("The header-cookie transport requires a script request")
    void headerCookieTransportRequiresXhr() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/refresh");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(TokenTransportType.HEADER_COOKIE).doFilter(request, response, new MockFilterChain());

        verify(responseWriter).writeErrorResponse(eq(response), eq(403), eq("REFRESH_REQUEST_REJECTED"), anyString(), anyString());
        verify(tokenService, never()).refresh(anyString());
    }

    @Test
    @DisplayName("A request without a refresh token is refused")
    void missingToken() throws Exception {
        MockHttpServletRequest request = refreshRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(TokenTransportType.HEADER).doFilter(request, response, new MockFilterChain());

        verify(responseWriter).writeErrorResponse(eq(response), eq(401), eq("REFRESH_TOKEN_MISSING"), anyString(), anyString());
    }

    @Test
    @DisplayName("Other requests pass through")
    void otherRequestsPass() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/refresh");
        MockFilterChain chain = new MockFilterChain();

        filter(TokenTransportType.COOKIE).doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    private OAuth2TokenRefreshFilter filter(TokenTransportType transportType) {
        return new OAuth2TokenRefreshFilter("/api/refresh", tokenService, transportType, responseWriter);
    }

    private static MockHttpServletRequest refreshRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/refresh");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        return request;
    }
}
