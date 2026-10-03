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
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;

/**
 * Shared handling of the token cookies of the cookie transport: renewing them through the token service,
 * which uses the Spring Authorization Server refresh_token grant, clearing them, and sending a browser
 * back to the page it asked for.
 */
@Slf4j
public final class OAuth2CookieTokenSupport {

    private final TokenService tokenService;

    public OAuth2CookieTokenSupport(TokenService tokenService) {
        Assert.notNull(tokenService, "tokenService cannot be null");
        this.tokenService = tokenService;
    }

    /**
     * Renews the token cookies with the refresh token cookie of the request. A renewal that yields the
     * access token that has just failed is treated as no renewal, so a browser is never sent around in
     * a loop with a token the server rejects.
     *
     * @return {@code true} when new token cookies were written to the response
     */
    public boolean refreshCookies(HttpServletRequest request, HttpServletResponse response,
                                  @Nullable String failedAccessToken) {
        String refreshToken = tokenService.resolveRefreshToken(request);
        if (!StringUtils.hasText(refreshToken)) {
            return false;
        }
        TokenService.RefreshResult result;
        try {
            result = tokenService.refresh(refreshToken);
        } catch (OAuth2AuthenticationException | OAuth2AuthorizationException ex) {
            // An expired, rotated or revoked refresh token is an ordinary end of the login.
            return false;
        } catch (RuntimeException ex) {
            log.error("Token cookie refresh failed unexpectedly", ex);
            return false;
        }
        if (result == null || !StringUtils.hasText(result.accessToken())
                || result.accessToken().equals(failedAccessToken)) {
            return false;
        }
        writeCookies(response, tokenService.prepareTokensForTransport(result.accessToken(), result.refreshToken()));
        return true;
    }

    public void clearCookies(HttpServletResponse response) {
        writeCookies(response, tokenService.prepareClearTokens());
    }

    public TokenService tokenService() {
        return tokenService;
    }

    @Nullable
    public String resolveAccessToken(HttpServletRequest request) {
        return tokenService.resolveAccessToken(request);
    }

    public boolean hasRefreshCookie(HttpServletRequest request) {
        return StringUtils.hasText(tokenService.resolveRefreshToken(request));
    }

    public boolean hasAccessToken(HttpServletRequest request) {
        return StringUtils.hasText(request.getHeader(HttpHeaders.AUTHORIZATION))
                || StringUtils.hasText(tokenService.resolveAccessToken(request));
    }

    /**
     * Whether the request is a page navigation of a browser: a GET for HTML that is neither an API nor
     * an XHR request. Only such requests are answered with a redirect.
     */
    public static boolean isPageNavigation(HttpServletRequest request) {
        if (!HttpMethod.GET.matches(request.getMethod()) || WebUtil.isApiOrAjaxRequest(request)) {
            return false;
        }
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        return accept != null && accept.contains(MediaType.TEXT_HTML_VALUE);
    }

    /**
     * Sends the browser to the same path and query on this application.
     */
    public static void redirectToSameUrl(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getQueryString();
        response.sendRedirect(request.getRequestURI() + (StringUtils.hasText(query) ? "?" + query : ""));
    }

    private static void writeCookies(HttpServletResponse response, @Nullable TokenTransportResult result) {
        if (result == null) {
            return;
        }
        write(response, result.getCookiesToSet());
        write(response, result.getCookiesToRemove());
    }

    private static void write(HttpServletResponse response, @Nullable List<ResponseCookie> cookies) {
        if (cookies == null) {
            return;
        }
        for (ResponseCookie cookie : cookies) {
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }
    }
}
