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
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HeaderCookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    public HeaderCookieTokenStrategy(AuthContextProperties props) {
        super(props);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String header = request.getHeader(TokenService.ACCESS_TOKEN_HEADER);
        if (header != null && header.startsWith(TokenService.BEARER_PREFIX)) {
            return header.substring(TokenService.BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN_COOKIE_NAME);
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken) {
        Map<String, Object> body = new HashMap<>();
        body.put("accessToken", accessToken);
        body.put("tokenType", "Bearer");
        body.put("expiresIn", accessTokenValidity);
        body.put("tokenTransportMethod", "HEADER_COOKIE");

        List<ResponseCookie> cookiesToSet = new ArrayList<>();
        if (StringUtils.hasText(refreshToken)) {
            ResponseCookie refreshCookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                    .path(DEFAULT_COOKIE_PATH)
                    .httpOnly(HTTP_ONLY)
                    .secure(cookieSecureFlag)
                    .sameSite(SAME_SITE)
                    .maxAge((int) (refreshTokenValidity / 1000))
                    .build();
            cookiesToSet.add(refreshCookie);
            body.put("refreshExpiresIn", refreshTokenValidity);
        }

        return TokenTransportResult.builder()
                .body(body)
                .cookiesToSet(cookiesToSet)
                .build();
    }

    @Override
    public TokenTransportResult prepareTokensForClear() {
        List<ResponseCookie> cookiesToRemove = new ArrayList<>();
        ResponseCookie expiredRefreshCookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .path(DEFAULT_COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(cookieSecureFlag)
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        cookiesToRemove.add(expiredRefreshCookie);

        return TokenTransportResult.builder()
                .cookiesToRemove(cookiesToRemove)
                .body(Map.of("message", "Tokens cleared by server instruction."))
                .build();
    }
}

