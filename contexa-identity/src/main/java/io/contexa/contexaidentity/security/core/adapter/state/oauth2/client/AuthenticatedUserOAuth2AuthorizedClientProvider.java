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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

@Slf4j
public class AuthenticatedUserOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

    private static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private OAuth2AccessTokenResponseClient<OAuth2AuthenticatedUserGrantRequest> accessTokenResponseClient =
            new RestClientAuthenticatedUserTokenResponseClient();

    public AuthenticatedUserOAuth2AuthorizedClientProvider() {
    }

    public void setAccessTokenResponseClient(
            OAuth2AccessTokenResponseClient<OAuth2AuthenticatedUserGrantRequest> accessTokenResponseClient) {
        Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    @Override
    @Nullable
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
        Assert.notNull(context, "context cannot be null");

        ClientRegistration clientRegistration = context.getClientRegistration();

        if (!AUTHENTICATED_USER.equals(clientRegistration.getAuthorizationGrantType())) {
            return null;
        }

        OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
        if (authorizedClient != null) {
            return null;
        }

        Authentication authentication = context.getPrincipal();
        if (authentication == null) {
            OAuth2Error error = new OAuth2Error("invalid_principal",
                    "Principal is required for authenticated-user grant", null);
            throw new OAuth2AuthenticationException(error);
        }

        String username = authentication.getName();
        String deviceId = context.getAttribute("device_id");

        HttpServletRequest request = context.getAttribute(HttpServletRequest.class.getName());
        HttpServletResponse response = context.getAttribute(HttpServletResponse.class.getName());

        OAuth2AuthenticatedUserGrantRequest grantRequest =
                new OAuth2AuthenticatedUserGrantRequest(clientRegistration, username, deviceId);

        if (this.accessTokenResponseClient instanceof RestClientAuthenticatedUserTokenResponseClient client) {
            client.setRequest(request);
            client.setResponse(response);
        } else {
            log.error("accessTokenResponseClient is not an instance of RestClientAuthenticatedUserTokenResponseClient: {}",
                    this.accessTokenResponseClient.getClass().getName());
        }

        OAuth2AccessTokenResponse tokenResponse;
        try {
            tokenResponse = this.accessTokenResponseClient.getTokenResponse(grantRequest);
        } catch (OAuth2AuthenticationException ex) {
            log.error("Failed to obtain access token for user '{}'", username, ex);
            throw ex;
        }

        return new OAuth2AuthorizedClient(
                clientRegistration,
                username,
                tokenResponse.getAccessToken(),
                tokenResponse.getRefreshToken());
    }
}
