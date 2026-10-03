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

import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Sends the refresh_token grant of the Spring OAuth2 client to the in-process Spring Authorization
 * Server token endpoint, so that validation and rotation are done by the authorization server itself.
 */
public final class InProcessRefreshTokenTokenResponseClient
        implements OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> {

    private final InProcessOAuth2TokenEndpoint tokenEndpoint;

    public InProcessRefreshTokenTokenResponseClient(InProcessOAuth2TokenEndpoint tokenEndpoint) {
        Assert.notNull(tokenEndpoint, "tokenEndpoint cannot be null");
        this.tokenEndpoint = tokenEndpoint;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2RefreshTokenGrantRequest grantRequest) {
        Assert.notNull(grantRequest, "grantRequest cannot be null");
        ClientRegistration clientRegistration = grantRequest.getClientRegistration();
        String refreshTokenValue = grantRequest.getRefreshToken().getTokenValue();

        OAuth2AccessTokenResponse tokenResponse = tokenEndpoint.exchange(null, null,
                request -> OAuth2TokenRequestWrapper.refreshToken(
                        request,
                        refreshTokenValue,
                        clientRegistration.getClientId(),
                        clientRegistration.getClientSecret()));

        if (tokenResponse.getRefreshToken() == null) {
            return OAuth2AccessTokenResponse.withResponse(tokenResponse).refreshToken(refreshTokenValue).build();
        }
        return tokenResponse;
    }
}
