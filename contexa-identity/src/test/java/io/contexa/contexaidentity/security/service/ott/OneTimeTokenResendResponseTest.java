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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.OneTimeTokenCreationSuccessHandler;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What the one asking sees: Spring Security's token filter and Contexa's success handler around the mail service. A
 * request the interval refused ends no flow, leads to no error page, keeps the user at the code, and reads as any other,
 * so nothing here tells whether an account exists.
 */
class OneTimeTokenResendResponseTest {

    private static final String REGISTERED = "alice";
    private static final String REGISTERED_ADDRESS = "alice@contexa.io";
    private static final String UNKNOWN = "nobody@contexa.io";

    private final EmailService mail = mock(EmailService.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
    private final MfaSessionRepository sessions = mock(MfaSessionRepository.class);
    private final AuthUrlProvider urls = new AuthUrlProvider(new AuthContextProperties());

    private EmailOneTimeTokenService service;
    private GenerateOneTimeTokenFilter filter;

    @BeforeEach
    void setUp() {
        when(mail.isMailSenderConfigured()).thenReturn(true);
        when(jdbc.queryForObject(anyString(), eq(String.class), eq(REGISTERED))).thenReturn(REGISTERED_ADDRESS);
        when(sessions.existsSession(anyString())).thenReturn(true);
        when(sessions.getRepositoryType()).thenReturn("memory");
        filterWith(true);
    }

    @AfterEach
    void stop() throws Exception {
        service.destroy();
    }

    private void filterWith(boolean failOnEmailError) {
        service = new EmailOneTimeTokenService(mail, jdbc, new TransactionTemplate(mock(PlatformTransactionManager.class)),
                new AuthContextProperties(), failOnEmailError, new InMemoryStepUpOptionsStore());
        filter = new GenerateOneTimeTokenFilter(service,
                new OneTimeTokenCreationSuccessHandler(integrator, urls, null, sessions));
        filter.setRequestMatcher(request -> true);
    }

    private MockHttpServletResponse post(String username) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mfa/ott/generate-code");
        request.setParameter("username", username);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private void inMfaFlowOf(String username) {
        FactorContext flow = mock(FactorContext.class);
        when(flow.getFlowTypeName()).thenReturn("mfa");
        when(flow.getUsername()).thenReturn(username);
        when(flow.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(flow.getMfaSessionId()).thenReturn("flow-1");
        when(integrator.loadFactorContextFromRequest(any())).thenReturn(flow);
    }

    private static String encoded(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("in an MFA flow every request goes on to the code page, and only the first one mails")
    void aRefusedRequestStaysAtTheCodePage() throws Exception {
        inMfaFlowOf(REGISTERED);

        MockHttpServletResponse first = post(REGISTERED);
        MockHttpServletResponse[] refused = {post(REGISTERED), post(REGISTERED), post(REGISTERED)};

        assertThat(first.getStatus()).isEqualTo(302);
        assertThat(first.getRedirectedUrl()).isEqualTo(urls.getOttChallengeUi());
        for (MockHttpServletResponse response : refused) {
            assertThat(response.getStatus()).isEqualTo(first.getStatus());
            assertThat(response.getRedirectedUrl()).isEqualTo(first.getRedirectedUrl());
        }
        verify(mail, times(1)).sendHtmlMessage(eq(REGISTERED_ADDRESS), anyString(), anyString());
    }

    @Test
    @DisplayName("a refused request moves the flow as a mailed one does, and ends nothing")
    void aRefusedRequestEndsNoFlow() throws Exception {
        inMfaFlowOf(REGISTERED);

        post(REGISTERED);
        post(REGISTERED);

        verify(integrator, times(2)).sendEvent(eq(MfaEvent.INITIATE_CHALLENGE), any(), any());
        verify(integrator, never()).sendEvent(eq(MfaEvent.SYSTEM_ERROR), any(), any());
        verify(integrator, never()).sendEvent(eq(MfaEvent.USER_ABORTED_MFA), any(), any());
    }

    @Test
    @DisplayName("a sign-in by code alone reads the same for the first request and the refused one")
    void aRefusedRequestOfASingleCodeSignInReadsTheSame() throws Exception {
        MockHttpServletResponse first = post(REGISTERED);
        MockHttpServletResponse refused = post(REGISTERED);

        assertThat(first.getRedirectedUrl()).contains("type=code_sent");
        assertThat(refused.getStatus()).isEqualTo(first.getStatus());
        assertThat(refused.getRedirectedUrl()).isEqualTo(first.getRedirectedUrl());
        verify(mail, times(1)).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("an account and no account read the same, sent and refused alike")
    void anAccountAndNoAccountReadTheSame() throws Exception {
        MockHttpServletResponse registeredFirst = post(REGISTERED);
        MockHttpServletResponse registeredRefused = post(REGISTERED);
        MockHttpServletResponse unknownFirst = post(UNKNOWN);
        MockHttpServletResponse unknownRefused = post(UNKNOWN);

        String registered = registeredFirst.getRedirectedUrl();
        assertThat(unknownFirst.getRedirectedUrl().replace(encoded(UNKNOWN), encoded(REGISTERED))).isEqualTo(registered);
        assertThat(unknownRefused.getRedirectedUrl().replace(encoded(UNKNOWN), encoded(REGISTERED))).isEqualTo(registered);
        assertThat(registeredRefused.getRedirectedUrl()).isEqualTo(registered);
        assertThat(unknownRefused.getStatus()).isEqualTo(registeredRefused.getStatus());
    }

    /** Before a sign-in the name is what the form says: mailed, the code would make the mail server a sender for anyone. */
    @Test
    @DisplayName("a name that is nobody's account is mailed nothing, however often it is asked for")
    void aNameOfNoAccountIsMailedNothing() throws Exception {
        post(UNKNOWN);
        post(UNKNOWN.toUpperCase(Locale.ROOT));
        post("another-" + UNKNOWN);

        verify(mail, never()).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    /** A name that is no address fails to mail each time and is never refused: the two must read the same. */
    @Test
    @DisplayName("a name whose mail fails reads as an account whose request was refused")
    void aFailedMailReadsAsARefusedRequest() throws Exception {
        service.destroy();
        filterWith(false);
        service.setUserStore(() -> new InMemoryUserDetailsManager(User.withUsername("nobody").password("{noop}x").build()));
        doThrow(new IllegalStateException("No such mailbox")).when(mail).sendHtmlMessage(eq("nobody"), anyString(), anyString());

        post(REGISTERED);
        MockHttpServletResponse refused = post(REGISTERED);
        MockHttpServletResponse failed = post("nobody");

        assertThat(failed.getStatus()).isEqualTo(refused.getStatus());
        assertThat(failed.getRedirectedUrl().replace("email=nobody", "email=" + encoded(REGISTERED)))
                .isEqualTo(refused.getRedirectedUrl());
    }
}
