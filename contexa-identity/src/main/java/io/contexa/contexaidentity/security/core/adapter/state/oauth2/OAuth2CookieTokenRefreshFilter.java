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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Keeps a cookie login alive across page navigations. The browser drops the access token cookie when the
 * token expires; when a page is then requested with only the refresh token cookie, the token cookies are
 * renewed through the token service and the browser is sent back to the same page. When the renewal is
 * refused the token cookies are removed and the request continues unauthenticated, so protected pages
 * lead to the sign-in page as before.
 *
 * <p>Requests of the page itself are renewed here; requests sent by its scripts are renewed by the SDK. The
 * filter therefore tells the rendered page, through request attributes read by the shared page head, that it
 * belongs to a cookie login and where the refresh entry point is.</p>
 */
public final class OAuth2CookieTokenRefreshFilter extends OncePerRequestFilter {

    /** Request attribute with the token transport of the page ({@code cookie}). */
    public static final String PAGE_TOKEN_TRANSPORT_ATTRIBUTE = "contexaTokenTransport";

    /** Request attribute with the URL of the refresh entry point, present when this chain serves it. */
    public static final String PAGE_REFRESH_URL_ATTRIBUTE = "contexaRefreshUrl";

    /** Request attribute with the URL of the SDK, which is served by this module rather than by the page owner. */
    public static final String PAGE_SDK_URL_ATTRIBUTE = "contexaSdkUrl";

    private static final String COOKIE_TRANSPORT = "cookie";
    private static final String SDK_PATH = "/js/contexa-mfa-sdk.js";

    private final OAuth2CookieTokenSupport cookieTokenSupport;
    @Nullable
    private final String refreshUri;

    public OAuth2CookieTokenRefreshFilter(OAuth2CookieTokenSupport cookieTokenSupport, @Nullable String refreshUri) {
        Assert.notNull(cookieTokenSupport, "cookieTokenSupport cannot be null");
        this.cookieTokenSupport = cookieTokenSupport;
        this.refreshUri = StringUtils.hasText(refreshUri) ? refreshUri : null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        request.setAttribute(PAGE_TOKEN_TRANSPORT_ATTRIBUTE, COOKIE_TRANSPORT);
        request.setAttribute(PAGE_SDK_URL_ATTRIBUTE, request.getContextPath() + SDK_PATH);
        if (refreshUri != null) {
            request.setAttribute(PAGE_REFRESH_URL_ATTRIBUTE, request.getContextPath() + refreshUri);
        }
        if (OAuth2CookieTokenSupport.isPageNavigation(request)
                && !cookieTokenSupport.hasAccessToken(request)
                && cookieTokenSupport.hasRefreshCookie(request)) {
            if (cookieTokenSupport.refreshCookies(request, response, null)) {
                OAuth2CookieTokenSupport.redirectToSameUrl(request, response);
                return;
            }
            cookieTokenSupport.clearCookies(response);
        }
        filterChain.doFilter(request, response);
    }
}
