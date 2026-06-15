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
package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseCookie;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenTransportStrategyTest {

    @Mock
    private AuthContextProperties properties;

    @Mock
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        when(properties.isCookieSecure()).thenReturn(true);
        when(properties.getAccessTokenValidity()).thenReturn(3600000L);
        when(properties.getRefreshTokenValidity()).thenReturn(604800000L);
    }

    @Test
    @DisplayName("CookieTokenStrategy resolve tokens from cookies")
    void cookieStrategyResolveTokens() {
        CookieTokenStrategy strategy = new CookieTokenStrategy(properties);

        Cookie accessCookie = new Cookie("accessToken", "access-token-123");
        Cookie refreshCookie = new Cookie("refreshToken", "refresh-token-123");
        when(request.getCookies()).thenReturn(new Cookie[]{accessCookie, refreshCookie});

        assertThat(strategy.resolveAccessToken(request)).isEqualTo("access-token-123");
        assertThat(strategy.resolveRefreshToken(request)).isEqualTo("refresh-token-123");
    }

    @Test
    @DisplayName("CookieTokenStrategy resolve tokens returns null when no cookies present")
    void cookieStrategyResolveTokensReturnsNull() {
        CookieTokenStrategy strategy = new CookieTokenStrategy(properties);
        when(request.getCookies()).thenReturn(null);

        assertThat(strategy.resolveAccessToken(request)).isNull();
        assertThat(strategy.resolveRefreshToken(request)).isNull();
    }

    @Test
    @DisplayName("CookieTokenStrategy prepare write should include cookies with valid security attributes")
    void cookieStrategyPrepareWrite() {
        CookieTokenStrategy strategy = new CookieTokenStrategy(properties);

        TokenTransportResult result = strategy.prepareTokensForWrite("access-123", "refresh-123");

        assertThat(result).isNotNull();
        assertThat(result.getBody()).containsEntry("status", "SUCCESS");
        assertThat(result.getBody()).containsEntry("tokenTransportMethod", "COOKIE");

        List<ResponseCookie> cookies = result.getCookiesToSet();
        assertThat(cookies).hasSize(2);

        ResponseCookie accessCookie = cookies.stream().filter(c -> "accessToken".equals(c.getName())).findFirst().orElseThrow();
        assertThat(accessCookie.getValue()).isEqualTo("access-123");
        assertThat(accessCookie.isHttpOnly()).isTrue();
        assertThat(accessCookie.isSecure()).isTrue();
        assertThat(accessCookie.getSameSite()).isEqualTo("Strict");
        assertThat(accessCookie.getPath()).isEqualTo("/");
        assertThat(accessCookie.getMaxAge().getSeconds()).isEqualTo(3600L);

        ResponseCookie refreshCookie = cookies.stream().filter(c -> "refreshToken".equals(c.getName())).findFirst().orElseThrow();
        assertThat(refreshCookie.getValue()).isEqualTo("refresh-123");
        assertThat(refreshCookie.getMaxAge().getSeconds()).isEqualTo(604800L);
    }

    @Test
    @DisplayName("CookieTokenStrategy prepare clear should produce cookies with maxAge 0")
    void cookieStrategyPrepareClear() {
        CookieTokenStrategy strategy = new CookieTokenStrategy(properties);

        TokenTransportResult result = strategy.prepareTokensForClear();

        assertThat(result).isNotNull();
        assertThat(result.getBody()).containsEntry("tokenTransportMethod", "COOKIE");

        List<ResponseCookie> cookies = result.getCookiesToRemove();
        assertThat(cookies).hasSize(2);

        ResponseCookie accessCookie = cookies.stream().filter(c -> "accessToken".equals(c.getName())).findFirst().orElseThrow();
        assertThat(accessCookie.getMaxAge().getSeconds()).isZero();

        ResponseCookie refreshCookie = cookies.stream().filter(c -> "refreshToken".equals(c.getName())).findFirst().orElseThrow();
        assertThat(refreshCookie.getMaxAge().getSeconds()).isZero();
    }

    @Test
    @DisplayName("HeaderTokenStrategy resolve tokens from headers")
    void headerStrategyResolveTokens() {
        HeaderTokenStrategy strategy = new HeaderTokenStrategy(properties);

        when(request.getHeader(TokenService.ACCESS_TOKEN_HEADER)).thenReturn("Bearer access-header-val");
        when(request.getHeader(TokenService.REFRESH_TOKEN_HEADER)).thenReturn("refresh-header-val");

        assertThat(strategy.resolveAccessToken(request)).isEqualTo("access-header-val");
        assertThat(strategy.resolveRefreshToken(request)).isEqualTo("refresh-header-val");
    }

    @Test
    @DisplayName("HeaderTokenStrategy resolve access token returns null on invalid header format")
    void headerStrategyResolveTokensReturnsNullOnInvalid() {
        HeaderTokenStrategy strategy = new HeaderTokenStrategy(properties);

        when(request.getHeader(TokenService.ACCESS_TOKEN_HEADER)).thenReturn("InvalidPrefix access-val");
        assertThat(strategy.resolveAccessToken(request)).isNull();
    }

    @Test
    @DisplayName("HeaderTokenStrategy prepare write should include tokens in body map")
    void headerStrategyPrepareWrite() {
        HeaderTokenStrategy strategy = new HeaderTokenStrategy(properties);

        TokenTransportResult result = strategy.prepareTokensForWrite("access-123", "refresh-123");

        assertThat(result).isNotNull();
        assertThat(result.getBody()).containsEntry("accessToken", "access-123");
        assertThat(result.getBody()).containsEntry("refreshToken", "refresh-123");
        assertThat(result.getBody()).containsEntry("tokenTransportMethod", "HEADER");
        assertThat(result.getBody()).containsEntry("expiresIn", 3600000L);
        assertThat(result.getBody()).containsEntry("refreshExpiresIn", 604800000L);
        assertThat(result.getCookiesToSet()).isNull();
    }

    @Test
    @DisplayName("HeaderTokenStrategy prepare clear should recommend client action")
    void headerStrategyPrepareClear() {
        HeaderTokenStrategy strategy = new HeaderTokenStrategy(properties);

        TokenTransportResult result = strategy.prepareTokensForClear();

        assertThat(result).isNotNull();
        assertThat(result.getBody()).containsEntry("tokenTransportMethod", "HEADER");
        assertThat(result.getBody()).containsEntry("action", "CLEAR_TOKENS");
        assertThat(result.getCookiesToRemove()).isNull();
    }

    @Test
    @DisplayName("HeaderCookieTokenStrategy resolve access token from header and refresh from cookie")
    void headerCookieStrategyResolveTokens() {
        HeaderCookieTokenStrategy strategy = new HeaderCookieTokenStrategy(properties);

        when(request.getHeader(TokenService.ACCESS_TOKEN_HEADER)).thenReturn("Bearer header-access-token");
        Cookie refreshCookie = new Cookie("refreshToken", "cookie-refresh-token");
        when(request.getCookies()).thenReturn(new Cookie[]{refreshCookie});

        assertThat(strategy.resolveAccessToken(request)).isEqualTo("header-access-token");
        assertThat(strategy.resolveRefreshToken(request)).isEqualTo("cookie-refresh-token");
    }

    @Test
    @DisplayName("HeaderCookieTokenStrategy prepare write should set access token in body and refresh in cookie")
    void headerCookieStrategyPrepareWrite() {
        HeaderCookieTokenStrategy strategy = new HeaderCookieTokenStrategy(properties);

        TokenTransportResult result = strategy.prepareTokensForWrite("access-123", "refresh-123");

        assertThat(result).isNotNull();
        assertThat(result.getBody()).containsEntry("accessToken", "access-123");
        assertThat(result.getBody()).containsEntry("tokenTransportMethod", "HEADER_COOKIE");
        assertThat(result.getBody()).containsEntry("expiresIn", 3600000L);
        assertThat(result.getBody()).containsEntry("refreshExpiresIn", 604800000L);

        List<ResponseCookie> cookies = result.getCookiesToSet();
        assertThat(cookies).hasSize(1);
        ResponseCookie refreshCookie = cookies.get(0);
        assertThat(refreshCookie.getName()).isEqualTo("refreshToken");
        assertThat(refreshCookie.getValue()).isEqualTo("refresh-123");
        assertThat(refreshCookie.getMaxAge().getSeconds()).isEqualTo(604800L);
    }

    @Test
    @DisplayName("HeaderCookieTokenStrategy prepare clear should expire refresh token cookie")
    void headerCookieStrategyPrepareClear() {
        HeaderCookieTokenStrategy strategy = new HeaderCookieTokenStrategy(properties);

        TokenTransportResult result = strategy.prepareTokensForClear();

        assertThat(result).isNotNull();
        List<ResponseCookie> cookies = result.getCookiesToRemove();
        assertThat(cookies).hasSize(1);
        ResponseCookie refreshCookie = cookies.get(0);
        assertThat(refreshCookie.getName()).isEqualTo("refreshToken");
        assertThat(refreshCookie.getMaxAge().getSeconds()).isZero();
    }
}
