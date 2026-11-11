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
package io.contexa.contexaidentity.security.filter.handler;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.mail.MessagingException;
import jakarta.mail.SendFailedException;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailParseException;
import org.springframework.mail.MailPreparationException;
import org.springframework.mail.MailSendException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A code asked for while the mail server cannot take it (down, the connection cut, no answer in time, the sender's
 * sign-in refused, the message refused) is answered as a service that is unavailable for a while, with what to do:
 * nothing was sent and the flow stays where it was, so the same request may be sent again. A message that could not be
 * made is no outage and stays the processing error it was, and so does a mail failure of any other request.
 */
class MfaCodeNotSentResponseTest {

    private static final String MFA_SESSION = "mfa-session-0815";
    private static final String MAIL_HOST = "smtp.internal.example:2525";
    private static final String NOT_SENT_MESSAGE = "The code could not be sent. Please try again in a moment.";

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(StateMachineAwareMfaRequestHandler.class);
    private FactorContext context;
    private StateMachineAwareMfaRequestHandler handler;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        MfaFlowUrlRegistry flowUrls = new MfaFlowUrlRegistry(properties);
        flowUrls.createAndRegister("mfa", null, null, null);
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        PlatformConfig platformConfig = mock(PlatformConfig.class);
        when(applicationContext.getBean(PlatformConfig.class)).thenReturn(platformConfig);
        when(platformConfig.getFlows()).thenReturn(List.of());
        context = new FactorContext(MFA_SESSION, UsernamePasswordAuthenticationToken.authenticated("user", null, List.of()),
                MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION, "mfa");
        when(integrator.loadFactorContextFromRequest(any())).thenReturn(context);
        handler = new StateMachineAwareMfaRequestHandler(properties, new JsonAuthResponseWriter(mapper), applicationContext,
                integrator, new AuthUrlProvider(properties), mock(MfaSessionRepository.class), flowUrls);
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    @Test
    @DisplayName("a mail server that is down or cut the connection: 503, what to do, the flow's session and state, no detail")
    void aMailServerThatCannotBeReachedIsUnavailable() throws Exception {
        MockHttpServletResponse response = codeRequestFails(new MailSendException("Mail server connection failed",
                new MessagingException("Got bad greeting from SMTP host: " + MAIL_HOST + ", response: [EOF]")));

        assertNotSent(response);
    }

    @Test
    @DisplayName("a mail server that refused the sender's sign-in is unavailable too: the user can do nothing about it")
    void aRefusedSignInOfTheSenderIsUnavailable() throws Exception {
        assertNotSent(codeRequestFails(new MailAuthenticationException("535 5.7.8 Authentication failed at " + MAIL_HOST)));
    }

    @Test
    @DisplayName("a message the mail server did not take (its recipient refused) did not leave either")
    void aMessageTheServerRefusedIsUnavailable() throws Exception {
        SendFailedException refused = new SendFailedException("550 5.1.1 mailbox unavailable at " + MAIL_HOST, null,
                new InternetAddress[0], new InternetAddress[0], new InternetAddress[] {new InternetAddress("user@corp.example")});
        assertNotSent(codeRequestFails(new MailSendException(Map.<Object, Exception>of(new Object(), refused))));
    }

    @Test
    @DisplayName("a mail failure that reached the handler wrapped is read by its cause")
    void aWrappedMailFailureIsUnavailable() throws Exception {
        assertNotSent(codeRequestFails(new ServletException("filter failed",
                new MailSendException("Mail server connection failed", new MessagingException("Read timed out")))));
    }

    @Test
    @DisplayName("a message that could not be made is no outage: it stays the processing error it was")
    void aMessageThatCouldNotBeMadeStaysAProcessingError() throws Exception {
        assertProcessingError(codeRequestFails(new MailParseException("Could not parse mail",
                new AddressException("Illegal address", "user@@corp"))));
        assertProcessingError(codeRequestFails(new MailPreparationException("Could not prepare mail")));
        assertProcessingError(codeRequestFails(new RuntimeException("Email sending failed",
                new AddressException("Illegal address", "user@@corp"))));
    }

    @Test
    @DisplayName("a mail failure of a request that does not ask for a code stays the processing error it was")
    void aMailFailureOfAnotherRequestStaysAProcessingError() throws Exception {
        FilterChain failing = mock(FilterChain.class);
        doThrow(new MailSendException("Mail server connection failed")).when(failing).doFilter(any(), any());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.LOGIN_PROCESSING, new MockHttpServletRequest("POST", "/login/webauthn"),
                response, context, failing);

        assertProcessingError(response);
    }

    @Test
    @DisplayName("nothing moves the flow on a code that was not sent, and the log keeps the failure as an error")
    void theFlowStaysAndTheLogKeepsTheFailure() throws Exception {
        codeRequestFails(new MailSendException("Mail server connection failed",
                new MessagingException("Couldn't connect to host " + MAIL_HOST)));

        verify(integrator, never()).sendEvent(any(), any(), any());
        assertThat(context.getCurrentState()).isEqualTo(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        assertThat(logged.list).anySatisfy(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage()).contains(MFA_SESSION);
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(MailSendException.class.getName());
        });
    }

    private void assertNotSent(MockHttpServletResponse response) throws Exception {
        assertThat(response.getStatus()).isEqualTo(503);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("status").asInt()).isEqualTo(503);
        assertThat(body.path("error").asText()).isEqualTo("OTT_CODE_NOT_SENT");
        assertThat(body.path("message").asText()).isEqualTo(NOT_SENT_MESSAGE);
        assertThat(body.path("success").asBoolean(true)).isFalse();
        assertThat(body.path("mfaSessionId").asText()).isEqualTo(MFA_SESSION);
        assertThat(body.path("currentState").asText())
                .isEqualTo(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION.name());
        assertThat(response.getContentAsString()).doesNotContain(MAIL_HOST, "Exception", "smtp");
    }

    private void assertProcessingError(MockHttpServletResponse response) throws Exception {
        assertThat(response.getStatus()).isEqualTo(500);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("REQUEST_PROCESSING_ERROR");
        assertThat(body.path("message").asText()).isEqualTo("An error occurred while processing the request.");
    }

    private MockHttpServletResponse codeRequestFails(Exception failure) throws Exception {
        FilterChain failing = mock(FilterChain.class);
        doThrow(failure).when(failing).doFilter(any(), any());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.OTT_CODE_REQUEST, new MockHttpServletRequest("POST", "/mfa/ott/generate-code"),
                response, context, failing);
        return response;
    }
}
