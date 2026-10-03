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
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Resolves the access token for the resource server when tokens travel in cookies: the Authorization
 * header is read first with the Spring default resolver, and only without it the access token cookie
 * issued by the cookie transport is used. The source is recorded on the request so that failures of a
 * cookie token can be answered differently from failures of a header token.
 *
 * <p>Only the bearer token filter uses this resolver. The resource server keeps the header resolver for
 * its CSRF exemption, so requests authenticated by cookie stay subject to CSRF protection.</p>
 */
public final class OAuth2AccessTokenResolver implements BearerTokenResolver {

    public static final String TOKEN_SOURCE_ATTRIBUTE = OAuth2AccessTokenResolver.class.getName() + ".SOURCE";
    public static final String COOKIE_SOURCE = "COOKIE";

    private final BearerTokenResolver headerResolver = new DefaultBearerTokenResolver();
    private final TokenService tokenService;

    public OAuth2AccessTokenResolver(TokenService tokenService) {
        Assert.notNull(tokenService, "tokenService cannot be null");
        this.tokenService = tokenService;
    }

    @Override
    public String resolve(HttpServletRequest request) {
        String headerToken = headerResolver.resolve(request);
        if (headerToken != null) {
            return headerToken;
        }
        String cookieToken = tokenService.resolveAccessToken(request);
        if (!StringUtils.hasText(cookieToken)) {
            return null;
        }
        request.setAttribute(TOKEN_SOURCE_ATTRIBUTE, COOKIE_SOURCE);
        return cookieToken;
    }

    public static boolean isCookieToken(HttpServletRequest request) {
        return COOKIE_SOURCE.equals(request.getAttribute(TOKEN_SOURCE_ATTRIBUTE));
    }
}
