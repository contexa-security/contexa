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

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WebAuthnFilterTest {

    @Mock
    private PublicKeyCredentialUserEntityRepository userEntities;

    @Mock
    private UserCredentialRepository userCredentials;

    @Mock
    private FilterChain filterChain;

    @Mock
    private MessageSource messageSource;

    @Test
    @DisplayName("RegistrationPageFilter passes through when request does not match GET /webauthn/register")
    void registrationPageFilterPassesThrough() throws Exception {
        ContexaWebAuthnRegistrationPageFilter filter = new ContexaWebAuthnRegistrationPageFilter(userEntities, userCredentials);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/webauthn/register");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("RegistrationPageFilter renders HTML correctly when request matches")
    void registrationPageFilterRendersHtml() throws Exception {
        ContexaWebAuthnRegistrationPageFilter filter = new ContexaWebAuthnRegistrationPageFilter(userEntities, userCredentials);
        filter.setMessageSource(messageSource);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ctx/webauthn/register");
        request.setContextPath("/ctx");
        request.setRemoteUser("testuser");
        request.setUserPrincipal(() -> "testuser");
        request.setPreferredLocales(List.of(Locale.KOREAN));

        CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "csrf-value-123");
        request.setAttribute(CsrfToken.class.getName(), csrfToken);

        MockHttpServletResponse response = new MockHttpServletResponse();

        PublicKeyCredentialUserEntity userEntity = mock(PublicKeyCredentialUserEntity.class);
        byte[] userIdBytes = new byte[]{1, 2, 3};
        Bytes userId = new Bytes(userIdBytes);
        when(userEntity.getId()).thenReturn(userId);
        when(userEntities.findByUsername("testuser")).thenReturn(userEntity);

        CredentialRecord record = mock(CredentialRecord.class);
        when(record.getLabel()).thenReturn("My Key");
        when(record.getCreated()).thenReturn(Instant.parse("2026-06-15T00:00:00Z"));
        when(record.getLastUsed()).thenReturn(Instant.parse("2026-06-15T05:00:00Z"));
        when(record.getSignatureCount()).thenReturn(5L);
        Bytes credId = new Bytes(new byte[]{4, 5, 6});
        when(record.getCredentialId()).thenReturn(credId);

        when(userCredentials.findByUserId(userId)).thenReturn(List.of(record));
        when(messageSource.getMessage(any(), any(), any(), any())).thenAnswer(invocation -> invocation.getArgument(2));

        filter.doFilterInternal(request, response, filterChain);

        assertThat(response.getContentType()).isEqualTo("text/html;charset=UTF-8");
        assertThat(response.getStatus()).isEqualTo(200);

        String resultHtml = response.getContentAsString();
        assertThat(resultHtml).contains("Passkey Management");
        assertThat(resultHtml).contains("My Key");
        assertThat(resultHtml).contains("csrf-value-123");
        assertThat(resultHtml).contains("/ctx/webauthn/register/BAUG");
    }

    @Test
    @DisplayName("ResourceFilter serves script when path matches")
    void resourceFilterServesScript() throws Exception {
        ContexaWebAuthnResourceFilter filter = ContexaWebAuthnResourceFilter.create("/webauthn/script.js");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/webauthn/script.js");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getContentType()).isEqualTo("text/javascript;charset=UTF-8");
        assertThat(response.getContentAsString()).isNotEmpty();
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("ResourceFilter passes through when path does not match")
    void resourceFilterPassesThrough() throws Exception {
        ContexaWebAuthnResourceFilter filter = ContexaWebAuthnResourceFilter.create("/webauthn/script.js");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/other/path");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }
}
