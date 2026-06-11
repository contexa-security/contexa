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

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

public class OAuth2AuthenticatedUserGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

    private static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private final String username;
    private final String deviceId;

    public OAuth2AuthenticatedUserGrantRequest(
            ClientRegistration clientRegistration,
            String username,
            @Nullable String deviceId) {

        super(AUTHENTICATED_USER, clientRegistration);
        Assert.hasText(username, "username cannot be empty");
        this.username = username;
        this.deviceId = deviceId;
    }

    public String getUsername() {
        return this.username;
    }

    @Nullable
    public String getDeviceId() {
        return this.deviceId;
    }
}
