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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Ends the tokens a sign-out carries. The refresh token ends its authorization, the access token with it; a sign-out that
 * carries the access token alone, as the HEADER transport sends it, ends the authorization the authorization service finds
 * for that token, so neither of its tokens works afterwards. A token that is no live one of this server ends nothing, and
 * the sign-out is answered as any other.
 * <p>
 * When the sign-out ends a person's sign-in, the tokens agents got by exchanging the person's tokens end with it, unless
 * a delegation of the person governs them ({@link ExchangedTokensOfASignOut}). An agent that signs out its own exchanged
 * token ends that token only.
 */
@Slf4j
public class OAuth2LogoutStrategy implements LogoutStrategy {

    private final TokenService tokenService;
    private final DeviceAwareOAuth2AuthorizationService authorizationService;
    private final ExchangedTokensOfASignOut exchangedTokens;

    public OAuth2LogoutStrategy(TokenService tokenService, DeviceAwareOAuth2AuthorizationService authorizationService,
                                ExchangedTokensOfASignOut exchangedTokens) {
        Assert.notNull(tokenService, "tokenService cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(exchangedTokens, "exchangedTokens cannot be null");
        this.tokenService = tokenService;
        this.authorizationService = authorizationService;
        this.exchangedTokens = exchangedTokens;
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
        Set<String> signedOut = new LinkedHashSet<>();

        String refreshToken = tokenService.resolveRefreshToken(request);
        if (refreshToken != null) {
            try {
                personOfRefreshToken(refreshToken, signedOut);
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
                endAuthorizationOf(accessToken, signedOut);
            } catch (Exception ex) {
                log.error("Unexpected error ending the sign-in of the access token for user {}: {}", username,
                        ex.getMessage(), ex);
            }
        }

        for (String person : signedOut) {
            try {
                exchangedTokens.end(person);
            } catch (Exception ex) {
                log.error("Unexpected error ending the exchanged tokens of a sign-out for user {}: {}", person,
                        ex.getMessage(), ex);
            }
        }
    }

    /** Notes the person whose live sign-in the refresh token is. */
    private void personOfRefreshToken(String refreshToken, Set<String> signedOut) {
        OAuth2Authorization authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            return;
        }
        OAuth2Authorization.Token<OAuth2RefreshToken> token = authorization.getRefreshToken();
        if (token != null && refreshToken.equals(token.getToken().getTokenValue()) && token.isActive()
                && isPersonsSignIn(authorization)) {
            signedOut.add(authorization.getPrincipalName());
        }
    }

    /** Ends the authorization the access token belongs to, when the token is a live one of it. */
    private void endAuthorizationOf(String accessToken, Set<String> signedOut) {
        OAuth2Authorization authorization = authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            return;
        }
        OAuth2Authorization.Token<OAuth2AccessToken> token = authorization.getAccessToken();
        if (token == null || !accessToken.equals(token.getToken().getTokenValue()) || !token.isActive()) {
            return;
        }
        authorizationService.invalidateAuthorization(authorization);
        if (isPersonsSignIn(authorization)) {
            signedOut.add(authorization.getPrincipalName());
        }
    }

    /** A person's sign-in, not a token a client got for itself or by exchanging someone's token. */
    private static boolean isPersonsSignIn(OAuth2Authorization authorization) {
        AuthorizationGrantType grant = authorization.getAuthorizationGrantType();
        return authorization.getPrincipalName() != null
                && !AuthorizationGrantType.TOKEN_EXCHANGE.equals(grant)
                && !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(grant);
    }
}
