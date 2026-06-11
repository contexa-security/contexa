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

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Set;

public final class AuthenticatedUserTokenRequestParametersConverter
        implements Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> {

    private static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:authenticated-user";

    @Override
    public MultiValueMap<String, String> convert(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

        parameters.add(OAuth2ParameterNames.GRANT_TYPE, GRANT_TYPE_VALUE);

        parameters.add("username", grantRequest.getUsername());

        if (grantRequest.getDeviceId() != null) {
            parameters.add("device_id", grantRequest.getDeviceId());
        }

        parameters.add(OAuth2ParameterNames.CLIENT_ID,
                grantRequest.getClientRegistration().getClientId());
        parameters.add(OAuth2ParameterNames.CLIENT_SECRET,
                grantRequest.getClientRegistration().getClientSecret());

        Set<String> scopes = grantRequest.getClientRegistration().getScopes();
        if (scopes != null && !scopes.isEmpty()) {
            parameters.add(OAuth2ParameterNames.SCOPE, String.join(" ", scopes));
        }

        return parameters;
    }
}
