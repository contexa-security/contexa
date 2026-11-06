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

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

/**
 * Ends the tokens a sign-out carries. The refresh token ends its authorization, the access token with it; a sign-out that
 * carries the access token alone, as the HEADER transport sends it, ends the authorization the authorization service finds
 * for that token, so neither of its tokens works afterwards. A token that is no live one of this server ends nothing, and
 * the sign-out is answered as any other.
 */
@Slf4j
public class OAuth2LogoutStrategy implements LogoutStrategy {

    private final TokenService tokenService;
    private final DeviceAwareOAuth2AuthorizationService authorizationService;

    public OAuth2LogoutStrategy(TokenService tokenService, DeviceAwareOAuth2AuthorizationService authorizationService) {
        Assert.notNull(tokenService, "tokenService cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.tokenService = tokenService;
        this.authorizationService = authorizationService;
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
        String username = (authentication != null) ? authentication.getName() : "UNKNOWN";

        String refreshToken = tokenService.resolveRefreshToken(request);
        if (refreshToken != null) {
            try {
                tokenService.invalidateRefreshToken(refreshToken);
            } catch (AuthenticationException ex) {
                log.error("Failed to invalidate tokens during logout for user {}: {}", username, ex.getMessage());
            } catch (Exception ex) {
                log.error("Unexpected error during token invalidation for user {}: {}", username, ex.getMessage(), ex);
            }
        }

        String accessToken = tokenService.resolveAccessToken(request);
        if (accessToken != null) {
            try {
                endAuthorizationOf(accessToken);
            } catch (Exception ex) {
                log.error("Unexpected error ending the sign-in of the access token for user {}: {}", username,
                        ex.getMessage(), ex);
            }
        }
    }

    /** Ends the authorization the access token belongs to, when the token is a live one of it. */
    private void endAuthorizationOf(String accessToken) {
        OAuth2Authorization authorization = authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            return;
        }
        OAuth2Authorization.Token<OAuth2AccessToken> token = authorization.getAccessToken();
        if (token == null || !accessToken.equals(token.getToken().getTokenValue()) || !token.isActive()) {
            return;
        }
        authorizationService.invalidateAuthorization(authorization);
    }
}
