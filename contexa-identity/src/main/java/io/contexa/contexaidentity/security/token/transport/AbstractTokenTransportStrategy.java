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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;

public abstract class AbstractTokenTransportStrategy {

    protected static final boolean HTTP_ONLY = true;
    protected static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    protected static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    protected static final String DEFAULT_COOKIE_PATH = "/";
    private static final List<String> SAME_SITE_VALUES = List.of("Strict", "Lax", "None");
    private static final AuthContextProperties DEFAULT_SETTINGS = new AuthContextProperties();

    protected final boolean cookieSecureFlag;
    protected final String sameSite;
    protected final long accessTokenValidity;
    protected final long refreshTokenValidity;

    protected AbstractTokenTransportStrategy(AuthContextProperties props) {
        AuthContextProperties settings = props != null ? props : DEFAULT_SETTINGS;
        this.cookieSecureFlag = props != null && props.isCookieSecure();
        this.sameSite = resolveSameSite(settings.getCookieSameSite(), cookieSecureFlag);
        this.accessTokenValidity = settings.getAccessTokenValidity();
        this.refreshTokenValidity = settings.getRefreshTokenValidity();
    }

    /**
     * A blank value keeps the default. Browsers drop a SameSite=None cookie that is not Secure, so that
     * combination fails at startup instead of silently losing the login cookies.
     */
    private static String resolveSameSite(String configured, boolean secure) {
        String value = StringUtils.hasText(configured) ? configured.trim() : DEFAULT_SETTINGS.getCookieSameSite();
        String sameSite = SAME_SITE_VALUES.stream()
                .filter(candidate -> candidate.equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "contexa.auth.cookie-same-site must be one of " + SAME_SITE_VALUES + ": " + configured));
        if ("None".equals(sameSite) && !secure) {
            throw new IllegalStateException(
                    "contexa.auth.cookie-same-site=None requires contexa.auth.cookie-secure=true");
        }
        return sameSite;
    }

    protected String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}

