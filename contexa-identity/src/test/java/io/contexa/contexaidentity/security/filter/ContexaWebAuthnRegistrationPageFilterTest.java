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
package io.contexa.contexaidentity.security.filter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ContexaWebAuthnRegistrationPageFilterTest {

    private final PublicKeyCredentialUserEntityRepository userEntities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository userCredentials = mock(UserCredentialRepository.class);
    private final ContexaWebAuthnRegistrationPageFilter filter =
            new ContexaWebAuthnRegistrationPageFilter(userEntities, userCredentials);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("An anonymous request is handed to the entry point instead of failing with 500")
    void anonymousRequestRequiresAuthentication() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertThatThrownBy(() -> filter.doFilter(registrationPage(null), new MockHttpServletResponse(), new MockFilterChain()))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verify(userEntities, never()).findByUsername(any());
    }

    @Test
    @DisplayName("A signed-in user gets the registration page")
    void signedInUserGetsThePage() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "admin", null, List.of()));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(registrationPage("admin"), response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).startsWith("text/html");
        verify(userEntities).findByUsername("admin");
    }

    private static MockHttpServletRequest registrationPage(String remoteUser) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/webauthn/register");
        request.setServletPath("/webauthn/register");
        request.setRemoteUser(remoteUser);
        return request;
    }
}
