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
package io.contexa.contexaidentity.security.token.wrapper;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The internal token request authenticates Contexa's client the way Spring's token endpoint reads it (RFC 6749 2.3.1:
 * form-encoded, then Basic). A secret with '+', '/', '=' or '%', such as a Base64 value, was decoded by Spring into a
 * different secret, and every sign-in of an OAuth2 flow failed with invalid_client (A7-0).
 */
class OAuth2TokenRequestWrapperTest {

    @Test
    void springReadsTheConfiguredClientIdAndSecret() {
        String secret = "k+9/Qw==%2Fz &x";
        OAuth2TokenRequestWrapper request = OAuth2TokenRequestWrapper.authenticatedUser(new MockHttpServletRequest(),
                "alice", null, "internal client", secret, Set.of("openid"));

        OAuth2ClientAuthenticationToken client = (OAuth2ClientAuthenticationToken)
                new ClientSecretBasicAuthenticationConverter().convert(request);

        assertThat(client).isNotNull();
        assertThat(client.getPrincipal()).isEqualTo("internal client");
        assertThat(client.getCredentials()).isEqualTo(secret);
    }
}
