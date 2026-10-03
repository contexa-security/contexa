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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticatedUserGrantAuthenticationConverterTest {

    private final AuthenticatedUserGrantAuthenticationConverter converter = new AuthenticatedUserGrantAuthenticationConverter();

    @BeforeEach
    void authenticateInternalClient() {
        RegisteredClient registeredClient = RegisteredClient.withId("internal-client-id")
                .clientId("internal-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("An external token request for the authenticated-user grant is left unconverted")
    void externalRequestIsNotConverted() {
        MockHttpServletRequest external = new MockHttpServletRequest("POST", "/oauth2/token");
        external.addParameter("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue());
        external.addParameter("username", "admin");

        assertThat(converter.convert(external)).isNull();
    }

    @Test
    @DisplayName("A token request built by the in-process token engine is converted")
    void internalRequestIsConverted() {
        OAuth2TokenRequestWrapper internal = OAuth2TokenRequestWrapper.authenticatedUser(
                new MockHttpServletRequest("POST", "/login"), "admin", "device-1",
                "internal-client", "secret", Set.of("read"));

        Authentication converted = converter.convert(internal);

        assertThat(converted).isInstanceOf(AuthenticatedUserGrantAuthenticationToken.class);
        AuthenticatedUserGrantAuthenticationToken token = (AuthenticatedUserGrantAuthenticationToken) converted;
        assertThat(token.getUsername()).isEqualTo("admin");
        assertThat(token.getDeviceId()).isEqualTo("device-1");
    }

    @Test
    @DisplayName("The internal marker does not leak into the wrapped request")
    void internalMarkerIsNotWrittenToTheOriginalRequest() {
        MockHttpServletRequest original = new MockHttpServletRequest("POST", "/login");
        OAuth2TokenRequestWrapper.authenticatedUser(original, "admin", null, "internal-client", "secret", Set.of());

        assertThat(original.getAttribute(OAuth2TokenRequestWrapper.INTERNAL_REQUEST_ATTRIBUTE)).isNull();
    }
}
