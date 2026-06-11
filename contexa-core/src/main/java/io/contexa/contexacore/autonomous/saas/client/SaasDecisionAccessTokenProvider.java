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
package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.util.StringUtils;

@RequiredArgsConstructor
public class SaasDecisionAccessTokenProvider {

    private final SaasForwardingProperties properties;
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final AnonymousAuthenticationToken principal = new AnonymousAuthenticationToken(
            "contexa-saas-client",
            "contexa-saas-client",
            AuthorityUtils.createAuthorityList("ROLE_SAAS_CLIENT"));

    public String getAccessToken() {
        properties.validate();
        SaasForwardingProperties.OAuth2 oauth2 = properties.getOauth2();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(oauth2.getRegistrationId())
                .principal(principal)
                .build();

        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
        if (authorizedClient == null || authorizedClient.getAccessToken() == null
                || !StringUtils.hasText(authorizedClient.getAccessToken().getTokenValue())) {
            throw new IllegalStateException("Failed to authorize SaaS forwarding OAuth2 client");
        }

        return authorizedClient.getAccessToken().getTokenValue();
    }
}
