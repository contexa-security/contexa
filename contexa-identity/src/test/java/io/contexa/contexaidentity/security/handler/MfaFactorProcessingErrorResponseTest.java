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
package io.contexa.contexaidentity.security.handler;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A factor that verified but left the flow in a state no step follows is answered with the error code and status it
 * always got and with general words: the state's name is the operators', in the log.
 */
class MfaFactorProcessingErrorResponseTest {

    private static final String USER = "alice.private";
    private static final String MFA_SESSION = "mfa-session-4711";
    private static final MfaState STRAY_STATE = MfaState.FACTOR_VERIFICATION_PENDING;

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(MfaFactorProcessingSuccessHandler.class);
    private final MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);

    @BeforeEach
    void listenToTheLog() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    @Test
    @DisplayName("the answer keeps its status and error code and says in general words that the step could not be processed")
    void theAnswerKeepsItsStatusAndErrorCode() throws Exception {
        MockHttpServletResponse response = verifiedFactorLeavesFlowIn(STRAY_STATE);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("MFA_PROCESSING_ERROR");
        assertThat(body.path("status").asInt()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertThat(body.path("path").asText()).isEqualTo("/contexa/mfa/verify");
        assertThat(body.path("message").asText()).isNotBlank();
        Set<String> fields = new TreeSet<>();
        body.fieldNames().forEachRemaining(fields::add);
        assertThat(fields).containsExactlyInAnyOrder("timestamp", "status", "error", "message", "path");
    }

    @Test
    @DisplayName("the answer does not name the state the flow was left in")
    void theAnswerDoesNotNameTheState() throws Exception {
        MockHttpServletResponse response = verifiedFactorLeavesFlowIn(STRAY_STATE);

        assertThat(response.getContentAsString()).doesNotContain(STRAY_STATE.name(), "Unexpected state");
    }

    @Test
    @DisplayName("the log keeps the state for the operators")
    void theLogKeepsTheState() throws Exception {
        verifiedFactorLeavesFlowIn(STRAY_STATE);

        assertThat(logged.list).anySatisfy(event -> assertThat(event.getFormattedMessage())
                .contains(STRAY_STATE.name(), USER));
    }

    @Test
    @DisplayName("the flow's state machine is released as it was")
    void theStateMachineIsReleased() throws Exception {
        verifiedFactorLeavesFlowIn(STRAY_STATE);

        verify(integrator).releaseStateMachine(eq(MFA_SESSION));
    }

    private MockHttpServletResponse verifiedFactorLeavesFlowIn(MfaState state) throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        MfaSessionRepository sessions = mock(MfaSessionRepository.class);
        when(sessions.existsSession(MFA_SESSION)).thenReturn(true);
        when(integrator.sendEvent(eq(MfaEvent.FACTOR_VERIFIED_SUCCESS), any(), any())).thenReturn(true);
        MfaFlowUrlRegistry flowUrls = mock(MfaFlowUrlRegistry.class);
        AuthUrlProvider urls = mock(AuthUrlProvider.class);
        MfaFactorProcessingSuccessHandler handler = new MfaFactorProcessingSuccessHandler(integrator,
                new JsonAuthResponseWriter(mapper), properties, sessions, mock(TokenService.class), urls, flowUrls,
                mock(ZeroTrustEventPublisher.class), mock(ZeroTrustActionRepository.class),
                mock(SecurityLearningService.class), mock(ApplicationContext.class), mock(IBlockedUserRecorder.class),
                mock(BlockMfaStateStore.class), mock(CentralAuditFacade.class), mock(BlockingSignalBroadcaster.class));

        Authentication authentication = new TestingAuthenticationToken(USER, "pw", "ROLE_USER");
        FactorContext flow = new FactorContext(MFA_SESSION, authentication, state, "mfa");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/mfa/verify");
        request.setAttribute("io.contexa.mfa.FactorContext", flow);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication);
        return response;
    }
}
