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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;

import java.io.IOException;

/**
 * Answers a rejected access token. A header token keeps the behaviour of the Spring default failure
 * handler, which hands over to the entry point. A cookie token is expired or revoked state left in the
 * browser: a page navigation first tries to renew the cookies and otherwise has them removed and is sent
 * back to the same page, which then continues unauthenticated; other requests get the cookies removed
 * and the entry point response.
 */
public final class OAuth2CookieTokenFailureHandler implements AuthenticationFailureHandler {

    private final OAuth2CookieTokenSupport cookieTokenSupport;
    private final AuthenticationEntryPoint entryPoint;

    public OAuth2CookieTokenFailureHandler(OAuth2CookieTokenSupport cookieTokenSupport,
                                           AuthenticationEntryPoint entryPoint) {
        Assert.notNull(cookieTokenSupport, "cookieTokenSupport cannot be null");
        Assert.notNull(entryPoint, "entryPoint cannot be null");
        this.cookieTokenSupport = cookieTokenSupport;
        this.entryPoint = entryPoint;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        if (exception instanceof AuthenticationServiceException) {
            throw exception;
        }
        if (!OAuth2AccessTokenResolver.isCookieToken(request)) {
            entryPoint.commence(request, response, exception);
            return;
        }
        if (OAuth2CookieTokenSupport.isPageNavigation(request)) {
            String rejectedToken = cookieTokenSupport.resolveAccessToken(request);
            if (!cookieTokenSupport.refreshCookies(request, response, rejectedToken)) {
                cookieTokenSupport.clearCookies(response);
            }
            OAuth2CookieTokenSupport.redirectToSameUrl(request, response);
            return;
        }
        cookieTokenSupport.clearCookies(response);
        entryPoint.commence(request, response, exception);
    }
}
