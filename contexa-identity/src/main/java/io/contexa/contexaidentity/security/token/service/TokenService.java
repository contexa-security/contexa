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
package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public interface TokenService extends TokenProvider, TokenValidator  {

    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    AuthContextProperties properties();
    record RefreshResult(String accessToken, String refreshToken) {}
    ObjectMapper getObjectMapper(); 

    default TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId) {
        
        String accessToken = createAccessToken(authentication, deviceId);
        String refreshToken = properties().isEnableRefreshToken()
                ? createRefreshToken(authentication, deviceId)
                : null;

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    default TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId,
                                     HttpServletRequest request, HttpServletResponse response) {
        return createTokenPair(authentication, deviceId);
    }

    TokenTransportResult prepareTokensForTransport(String accessToken, String refreshToken);
    TokenTransportResult prepareClearTokens();
    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);
}

