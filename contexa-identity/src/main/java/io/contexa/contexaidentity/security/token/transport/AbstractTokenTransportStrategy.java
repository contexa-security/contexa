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

import java.io.IOException;

public abstract class AbstractTokenTransportStrategy {

    protected static final String SAME_SITE = "Strict";
    protected static final boolean HTTP_ONLY = true;
    protected static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    protected static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    protected static final String DEFAULT_COOKIE_PATH = "/";

    protected final boolean cookieSecureFlag;
    protected final long accessTokenValidity;
    protected final long refreshTokenValidity;

    protected AbstractTokenTransportStrategy(AuthContextProperties props) {
        this.cookieSecureFlag = props != null && props.isCookieSecure();
        this.accessTokenValidity = props != null ? props.getAccessTokenValidity() : 3600000L;
        this.refreshTokenValidity = props != null ? props.getRefreshTokenValidity() : 604800000L;
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

