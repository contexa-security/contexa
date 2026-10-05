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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Obtains tokens for the authenticated-user grant from the in-process Spring Authorization Server
 * token endpoint.
 */
public final class InProcessAuthenticatedUserTokenResponseClient
        implements OAuth2AccessTokenResponseClient<OAuth2AuthenticatedUserGrantRequest> {

    private final InProcessOAuth2TokenEndpoint tokenEndpoint;
    private final ThreadLocal<HttpServletRequest> requestHolder = new ThreadLocal<>();
    private final ThreadLocal<HttpServletResponse> responseHolder = new ThreadLocal<>();

    public InProcessAuthenticatedUserTokenResponseClient(InProcessOAuth2TokenEndpoint tokenEndpoint) {
        Assert.notNull(tokenEndpoint, "tokenEndpoint cannot be null");
        this.tokenEndpoint = tokenEndpoint;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        Assert.notNull(grantRequest, "grantRequest cannot be null");
        ClientRegistration clientRegistration = grantRequest.getClientRegistration();
        try {
            return tokenEndpoint.exchange(requestHolder.get(), responseHolder.get(),
                    request -> OAuth2TokenRequestWrapper.authenticatedUser(
                            request,
                            grantRequest.getUsername(),
                            grantRequest.getDeviceId(),
                            clientRegistration.getClientId(),
                            clientRegistration.getClientSecret(),
                            clientRegistration.getScopes()));
        } finally {
            requestHolder.remove();
            responseHolder.remove();
        }
    }

    public void setRequest(HttpServletRequest request) {
        this.requestHolder.set(request);
    }

    public void setResponse(HttpServletResponse response) {
        this.responseHolder.set(response);
    }
}
