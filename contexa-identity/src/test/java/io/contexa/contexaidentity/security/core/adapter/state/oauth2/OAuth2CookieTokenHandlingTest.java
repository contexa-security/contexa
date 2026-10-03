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

import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2CookieTokenHandlingTest {

    private static final String REFRESH_URI = "/api/refresh";

    private TokenService tokenService;
    private OAuth2CookieTokenSupport support;

    @BeforeEach
    void setUp() {
        tokenService = mock(TokenService.class);
        support = new OAuth2CookieTokenSupport(tokenService);
        when(tokenService.prepareTokensForTransport(anyString(), any())).thenAnswer(invocation ->
                TokenTransportResult.builder().cookiesToSet(List.of(
                        ResponseCookie.from("accessToken", invocation.getArgument(0)).path("/").build(),
                        ResponseCookie.from("refreshToken", "rotated-refresh").path("/").build())).build());
        when(tokenService.prepareClearTokens()).thenReturn(TokenTransportResult.builder().cookiesToRemove(List.of(
                ResponseCookie.from("accessToken", "").maxAge(0).path("/").build(),
                ResponseCookie.from("refreshToken", "").maxAge(0).path("/").build())).build());
    }

    @Nested
    @DisplayName("Access token resolution")
    class Resolution {

        @Test
        @DisplayName("The Authorization header wins over the cookie")
        void headerFirst() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
            request.addHeader("Authorization", "Bearer header-token");
            when(tokenService.resolveAccessToken(request)).thenReturn("cookie-token");

            assertThat(new OAuth2AccessTokenResolver(tokenService).resolve(request)).isEqualTo("header-token");
            assertThat(OAuth2AccessTokenResolver.isCookieToken(request)).isFalse();
        }

        @Test
        @DisplayName("Without a header the access token cookie is used and marked as such")
        void cookieFallback() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
            when(tokenService.resolveAccessToken(request)).thenReturn("cookie-token");

            assertThat(new OAuth2AccessTokenResolver(tokenService).resolve(request)).isEqualTo("cookie-token");
            assertThat(OAuth2AccessTokenResolver.isCookieToken(request)).isTrue();
        }

        @Test
        @DisplayName("Without header and cookie no token is resolved")
        void noToken() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");

            assertThat(new OAuth2AccessTokenResolver(tokenService).resolve(request)).isNull();
        }
    }

    @Nested
    @DisplayName("Rejected access tokens")
    class Failures {

        private final AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        private final InvalidBearerTokenException rejected = new InvalidBearerTokenException("expired");

        @Test
        @DisplayName("A rejected header token keeps the entry point response")
        void headerTokenUsesEntryPoint() throws Exception {
            MockHttpServletRequest request = pageRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();

            new OAuth2CookieTokenFailureHandler(support, entryPoint).onAuthenticationFailure(request, response, rejected);

            verify(entryPoint).commence(request, response, rejected);
            assertThat(response.getHeaders("Set-Cookie")).isEmpty();
        }

        @Test
        @DisplayName("A rejected cookie on a page navigation is renewed and the page is requested again")
        void cookieTokenRenewedOnPageNavigation() throws Exception {
            MockHttpServletRequest request = cookiePageRequest("expired-access");
            when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
            when(tokenService.refresh("refresh")).thenReturn(new TokenService.RefreshResult("new-access", "rotated-refresh"));
            MockHttpServletResponse response = new MockHttpServletResponse();

            new OAuth2CookieTokenFailureHandler(support, entryPoint).onAuthenticationFailure(request, response, rejected);

            assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/dashboard?tab=1");
            assertThat(response.getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("accessToken=new-access"));
            verify(entryPoint, never()).commence(any(), any(), any());
        }

        @Test
        @DisplayName("A renewal returning the rejected token clears the cookies instead of looping")
        void sameTokenIsNotARenewal() throws Exception {
            MockHttpServletRequest request = cookiePageRequest("revoked-access");
            when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
            when(tokenService.refresh("refresh")).thenReturn(new TokenService.RefreshResult("revoked-access", "refresh"));
            MockHttpServletResponse response = new MockHttpServletResponse();

            new OAuth2CookieTokenFailureHandler(support, entryPoint).onAuthenticationFailure(request, response, rejected);

            assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/dashboard?tab=1");
            assertThat(response.getHeaders("Set-Cookie")).allMatch(c -> c.contains("Max-Age=0"));
        }

        @Test
        @DisplayName("A refused renewal clears the cookies and requests the page again unauthenticated")
        void refusedRenewalClearsCookies() throws Exception {
            MockHttpServletRequest request = cookiePageRequest("expired-access");
            when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
            when(tokenService.refresh("refresh")).thenThrow(new OAuth2AuthenticationException(new OAuth2Error("invalid_token")));
            MockHttpServletResponse response = new MockHttpServletResponse();

            new OAuth2CookieTokenFailureHandler(support, entryPoint).onAuthenticationFailure(request, response, rejected);

            assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/dashboard?tab=1");
            assertThat(response.getHeaders("Set-Cookie")).hasSize(2).allMatch(c -> c.contains("Max-Age=0"));
        }

        @Test
        @DisplayName("A rejected cookie on an API request clears the cookies and returns the entry point response")
        void cookieTokenOnApiRequest() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/api/blacklist");
            request.addHeader("Accept", "application/json");
            request.setAttribute(OAuth2AccessTokenResolver.TOKEN_SOURCE_ATTRIBUTE, OAuth2AccessTokenResolver.COOKIE_SOURCE);
            MockHttpServletResponse response = new MockHttpServletResponse();

            new OAuth2CookieTokenFailureHandler(support, entryPoint).onAuthenticationFailure(request, response, rejected);

            verify(entryPoint).commence(request, response, rejected);
            verify(tokenService, never()).refresh(anyString());
            assertThat(response.getHeaders("Set-Cookie")).allMatch(c -> c.contains("Max-Age=0"));
        }

        private MockHttpServletRequest cookiePageRequest(String accessToken) {
            MockHttpServletRequest request = pageRequest();
            request.setAttribute(OAuth2AccessTokenResolver.TOKEN_SOURCE_ATTRIBUTE, OAuth2AccessTokenResolver.COOKIE_SOURCE);
            when(tokenService.resolveAccessToken(request)).thenReturn(accessToken);
            return request;
        }
    }

    @Nested
    @DisplayName("Page navigation without an access token cookie")
    class Navigation {

        @Test
        @DisplayName("With a refresh cookie the cookies are renewed and the page is requested again")
        void renewsAndRedirects() throws Exception {
            MockHttpServletRequest request = pageRequest();
            when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
            when(tokenService.refresh("refresh")).thenReturn(new TokenService.RefreshResult("new-access", "rotated-refresh"));
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            new OAuth2CookieTokenRefreshFilter(support, REFRESH_URI).doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/admin/dashboard?tab=1");
            assertThat(response.getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("accessToken=new-access"));
        }

        @Test
        @DisplayName("A refused renewal clears the cookies and lets the request continue")
        void refusedRenewalContinues() throws Exception {
            MockHttpServletRequest request = pageRequest();
            when(tokenService.resolveRefreshToken(request)).thenReturn("refresh");
            when(tokenService.refresh("refresh")).thenThrow(new OAuth2AuthenticationException(new OAuth2Error("invalid_token")));
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            new OAuth2CookieTokenRefreshFilter(support, REFRESH_URI).doFilter(request, response, chain);

            assertThat(chain.getRequest()).isSameAs(request);
            assertThat(response.getHeaders("Set-Cookie")).hasSize(2).allMatch(c -> c.contains("Max-Age=0"));
        }

        @Test
        @DisplayName("API requests and requests with an access token are left alone")
        void otherRequestsPass() throws Exception {
            MockHttpServletRequest api = new MockHttpServletRequest("GET", "/contexa/admin/api/blacklist");
            api.addHeader("Accept", "application/json");
            when(tokenService.resolveRefreshToken(api)).thenReturn("refresh");
            MockHttpServletRequest withToken = pageRequest();
            when(tokenService.resolveAccessToken(withToken)).thenReturn("valid-access");
            when(tokenService.resolveRefreshToken(withToken)).thenReturn("refresh");

            for (MockHttpServletRequest request : List.of(api, withToken)) {
                MockFilterChain chain = new MockFilterChain();
                new OAuth2CookieTokenRefreshFilter(support, REFRESH_URI).doFilter(request, new MockHttpServletResponse(), chain);
                assertThat(chain.getRequest()).isSameAs(request);
            }
            verify(tokenService, never()).refresh(anyString());
        }

        @Test
        @DisplayName("Every request tells the rendered page that it belongs to a cookie login and where to renew")
        void marksTheRenderedPage() throws Exception {
            MockHttpServletRequest withToken = pageRequest();
            withToken.setContextPath("/app");
            when(tokenService.resolveAccessToken(withToken)).thenReturn("valid-access");

            new OAuth2CookieTokenRefreshFilter(support, REFRESH_URI).doFilter(withToken, new MockHttpServletResponse(), new MockFilterChain());

            assertThat(withToken.getAttribute(OAuth2CookieTokenRefreshFilter.PAGE_TOKEN_TRANSPORT_ATTRIBUTE)).isEqualTo("cookie");
            assertThat(withToken.getAttribute(OAuth2CookieTokenRefreshFilter.PAGE_REFRESH_URL_ATTRIBUTE)).isEqualTo("/app" + REFRESH_URI);
            assertThat(withToken.getAttribute(OAuth2CookieTokenRefreshFilter.PAGE_SDK_URL_ATTRIBUTE)).isEqualTo("/app/js/contexa-mfa-sdk.js");
        }

        @Test
        @DisplayName("Without a refresh entry point in the chain no refresh URL is offered to the page")
        void noRefreshUrlWithoutEntryPoint() throws Exception {
            MockHttpServletRequest withToken = pageRequest();
            when(tokenService.resolveAccessToken(withToken)).thenReturn("valid-access");

            new OAuth2CookieTokenRefreshFilter(support, null).doFilter(withToken, new MockHttpServletResponse(), new MockFilterChain());

            assertThat(withToken.getAttribute(OAuth2CookieTokenRefreshFilter.PAGE_TOKEN_TRANSPORT_ATTRIBUTE)).isEqualTo("cookie");
            assertThat(withToken.getAttribute(OAuth2CookieTokenRefreshFilter.PAGE_REFRESH_URL_ATTRIBUTE)).isNull();
        }
    }

    private static MockHttpServletRequest pageRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/dashboard");
        request.setQueryString("tab=1");
        request.addHeader("Accept", "text/html,application/xhtml+xml");
        return request;
    }
}
