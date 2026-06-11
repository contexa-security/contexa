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
package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

@Slf4j
public class OAuth2LogoutStrategy implements LogoutStrategy {

    private static final String REASON_LOGOUT = "LOGOUT";

    private final TokenService tokenService;

    public OAuth2LogoutStrategy(TokenService tokenService) {
        Assert.notNull(tokenService, "tokenService cannot be null");
        this.tokenService = tokenService;
    }

    @Override
    public boolean supports(HttpServletRequest request, Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken) {
            return true;
        }
        return tokenService.resolveAccessToken(request) != null
                || tokenService.resolveRefreshToken(request) != null;
    }

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = tokenService.resolveRefreshToken(request);
        String username = (authentication != null) ? authentication.getName() : "UNKNOWN";

        if (refreshToken == null) {
            return;
        }

        try {
            tokenService.invalidateRefreshToken(refreshToken);
        } catch (AuthenticationException ex) {
            log.error("Failed to invalidate tokens during logout for user {}: {}", username, ex.getMessage());
        } catch (Exception ex) {
            log.error("Unexpected error during token invalidation for user {}: {}", username, ex.getMessage(), ex);
        }
    }
}
