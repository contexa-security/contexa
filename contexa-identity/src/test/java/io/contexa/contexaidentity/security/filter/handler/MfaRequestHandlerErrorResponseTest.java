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
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A request of the MFA flow that fails inside answers the client that it failed and no more: the exception's type and
 * text name what failed inside (a store, a host, a state) and are the operators', in the log. The client keeps what
 * every answer of the flow carries: the status, the error code, the flow's session and state.
 */
class MfaRequestHandlerErrorResponseTest {

    private static final String MFA_SESSION = "mfa-session-4711";
    private static final String INTERNAL_CAUSE = "jdbc:postgresql://db.internal:5432/contexa refused the connection";

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
    @DisplayName("a request that fails while it is processed is answered with the same status and error code, and no exception detail")
    void aProcessingFailureIsAnsweredWithoutTheException() throws Exception {
        MockHttpServletResponse response = processingFails(new IllegalStateException(INTERNAL_CAUSE));

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("REQUEST_PROCESSING_ERROR");
        assertThat(body.path("message").asText()).isEqualTo("An error occurred while processing the request.");
        assertThat(body.path("success").asBoolean(true)).isFalse();
        assertThat(body.path("mfaSessionId").asText()).as("the flow's own session, as every answer of the flow carries it")
                .isEqualTo(MFA_SESSION);
        assertThat(body.path("currentState").asText()).isEqualTo(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION.name());
        assertThat(fieldsOf(body)).doesNotContain("errorType", "errorMessage");
        assertThat(response.getContentAsString()).doesNotContain(INTERNAL_CAUSE, "IllegalStateException");
    }

    @Test
    @DisplayName("the log keeps the exception of a failed request for the operators")
    void theLogKeepsTheExceptionOfAFailedRequest() throws Exception {
        processingFails(new IllegalStateException(INTERNAL_CAUSE));

        assertThat(logged.list).anySatisfy(event -> {
            assertThat(event.getFormattedMessage()).contains(MFA_SESSION);
            assertThat(event.getThrowableProxy()).isNotNull();
            assertThat(event.getThrowableProxy().getMessage()).isEqualTo(INTERNAL_CAUSE);
        });
    }

    @Test
    @DisplayName("an error that reaches the filter is answered with the same status and error code, and no exception detail")
    void aGenericErrorIsAnsweredWithoutTheException() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/mfa/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleGenericError(request, response, context, new IllegalStateException(INTERNAL_CAUSE));

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("MFA_PROCESSING_ERROR");
        assertThat(body.path("message").asText()).isEqualTo("A system error occurred during MFA processing.");
        assertThat(response.getContentAsString()).doesNotContain(INTERNAL_CAUSE, "IllegalStateException");
        assertThat(logged.list).anySatisfy(event -> assertThat(event.getThrowableProxy().getMessage())
                .isEqualTo(INTERNAL_CAUSE));
    }

    @Test
    @DisplayName("whatever writes the response, the text it is handed is not the exception's")
    void theWriterIsNotHandedTheExceptionText() throws Exception {
        AuthResponseWriter writer = mock(AuthResponseWriter.class);
        AuthContextProperties properties = new AuthContextProperties();
        MfaFlowUrlRegistry flowUrls = new MfaFlowUrlRegistry(properties);
        flowUrls.createAndRegister("mfa", null, null, null);
        StateMachineAwareMfaRequestHandler other = new StateMachineAwareMfaRequestHandler(properties, writer,
                mock(ApplicationContext.class), integrator, new AuthUrlProvider(properties),
                mock(MfaSessionRepository.class), flowUrls);

        other.handleGenericError(new MockHttpServletRequest("POST", "/contexa/mfa/verify"), new MockHttpServletResponse(),
                context, new IllegalStateException(INTERNAL_CAUSE));

        verify(writer).writeErrorResponse(any(), eq(500), eq("MFA_PROCESSING_ERROR"),
                argThat(text -> text != null && !text.contains(INTERNAL_CAUSE)), any(), any());
    }

    @Test
    @DisplayName("a request of a kind the flow has no step for is answered with its status and error code, and not the kind's name")
    void anUnsupportedRequestIsAnsweredWithoutTheKindsName() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/mfa/anything");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.UNKNOWN, request, response, context, mock(FilterChain.class));

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("UNSUPPORTED_REQUEST");
        assertThat(body.path("message").asText()).isEqualTo("Unsupported request type");
        assertThat(body.path("success").asBoolean(true)).isFalse();
        assertThat(body.path("mfaSessionId").asText()).isEqualTo(MFA_SESSION);
        assertThat(response.getContentAsString()).doesNotContain(MfaRequestType.UNKNOWN.getDescription());
    }

    @Test
    @DisplayName("the log keeps the kind of an unsupported request for the operators")
    void theLogKeepsTheKindOfAnUnsupportedRequest() throws Exception {
        handler.handleRequest(MfaRequestType.UNKNOWN, new MockHttpServletRequest("GET", "/contexa/mfa/anything"),
                new MockHttpServletResponse(), context, mock(FilterChain.class));

        assertThat(logged.list).anySatisfy(event -> assertThat(event.getFormattedMessage())
                .contains(MfaRequestType.UNKNOWN.name(), MFA_SESSION));
    }

    @Test
    @DisplayName("a flow found in a terminal state no answer is written for is answered with its status and error code, and not the state's name in words")
    void anUnknownTerminalStateIsAnsweredWithoutTheStateInTheMessage() throws Exception {
        context.changeState(MfaState.MFA_SESSION_INVALIDATED);
        when(integrator.getCurrentState(MFA_SESSION)).thenReturn(MfaState.MFA_SESSION_INVALIDATED);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/mfa/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleTerminalContext(request, response, context);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("UNKNOWN_STATE");
        assertThat(body.path("status").asText()).isEqualTo("UNKNOWN_TERMINAL_STATE");
        assertThat(body.path("message").asText()).isNotBlank().doesNotContain(MfaState.MFA_SESSION_INVALIDATED.name(),
                "Unknown terminal state");
        assertThat(body.path("terminal").asBoolean(false)).isTrue();
    }

    @Test
    @DisplayName("the log keeps the state of a flow found in a terminal state no answer is written for")
    void theLogKeepsTheUnknownTerminalState() throws Exception {
        context.changeState(MfaState.MFA_SESSION_INVALIDATED);
        when(integrator.getCurrentState(MFA_SESSION)).thenReturn(MfaState.MFA_SESSION_INVALIDATED);

        handler.handleTerminalContext(new MockHttpServletRequest("POST", "/contexa/mfa/verify"),
                new MockHttpServletResponse(), context);

        assertThat(logged.list).anySatisfy(event -> assertThat(event.getFormattedMessage())
                .contains(MfaState.MFA_SESSION_INVALIDATED.name(), MFA_SESSION));
    }

    private MockHttpServletResponse processingFails(RuntimeException failure) throws Exception {
        FilterChain failing = mock(FilterChain.class);
        doThrow(failure).when(failing).doFilter(any(), any());
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/login/process");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.LOGIN_PROCESSING, request, response, context, failing);
        return response;
    }

    private static Set<String> fieldsOf(JsonNode body) {
        Set<String> fields = new TreeSet<>();
        body.fieldNames().forEachRemaining(fields::add);
        return fields;
    }
}
