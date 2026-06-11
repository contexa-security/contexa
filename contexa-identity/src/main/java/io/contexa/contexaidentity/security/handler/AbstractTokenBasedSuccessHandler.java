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
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.Map;

@Slf4j
public abstract class AbstractTokenBasedSuccessHandler implements PlatformAuthenticationSuccessHandler {

    protected final TokenService tokenService;
    protected final AuthResponseWriter responseWriter;
    protected final AuthContextProperties authContextProperties;
    private volatile PlatformAuthenticationSuccessHandler delegateHandler;
    protected volatile String defaultTargetUrl;
    protected volatile boolean alwaysUse;

    protected AbstractTokenBasedSuccessHandler(TokenService tokenService,
                                               AuthResponseWriter responseWriter,
                                               AuthContextProperties authContextProperties) {
        this.tokenService = tokenService;
        this.responseWriter = responseWriter;
        this.authContextProperties = authContextProperties;
    }

    public void setDelegateHandler(@Nullable PlatformAuthenticationSuccessHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
    }

    @Override
    public void setDefaultTargetUrl(String defaultTargetUrl) {
        this.defaultTargetUrl = defaultTargetUrl;
    }

    @Override
    public void setAlwaysUse(boolean alwaysUse) {
        this.alwaysUse = alwaysUse;
    }

    protected TokenPair createTokenPair(Authentication authentication, String deviceId,
                                        HttpServletRequest request, HttpServletResponse response) {
        if (tokenService == null) {
            throw new IllegalStateException(
                    "TokenService is required for token creation but not configured. "
                            + "Ensure OAuth2 state configuration is enabled.");
        }
        return tokenService.createTokenPair(authentication, deviceId, request, response);
    }

    protected TokenTransportResult prepareTokenTransport(String accessToken, String refreshToken) {
        if (tokenService == null) {
            throw new IllegalStateException(
                    "TokenService is required for token transport but not configured. "
                            + "Ensure OAuth2 state configuration is enabled.");
        }
        return tokenService.prepareTokensForTransport(accessToken, refreshToken);
    }

    protected void setCookies(HttpServletResponse response, TokenTransportResult transportResult) {
        if (transportResult != null && transportResult.getCookiesToSet() != null) {
            for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }
    }

    protected void writeJsonResponse(HttpServletResponse response, Map<String, Object> responseData) throws IOException {
        responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
    }

    protected abstract Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                             Authentication authentication,
                                                             HttpServletRequest request,
                                                             HttpServletResponse response);

    protected abstract String determineTargetUrl(HttpServletRequest request, HttpServletResponse response);

    protected final boolean executeDelegateHandler(HttpServletRequest request,
                                                   HttpServletResponse response,
                                                   Authentication authentication,
                                                   @Nullable TokenTransportResult result) throws IOException {
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationSuccess(request, response, authentication, result);
                return true;
            } catch (Exception e) {
                log.error("Error in delegate success handler", e);
            }
        }
        return false;
    }

    protected String extractClientIp(HttpServletRequest request) {
        return SessionFingerprintUtil.extractClientIp(request);
    }
}
