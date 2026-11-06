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
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A sign-in whose processing after the success fails answers the client that it failed and no more: the person's name,
 * the failing step, the exception's type and text and the MFA session's identifier are the operators', in the log, and
 * not a client's to read.
 */
class MfaPostSuccessFailureResponseTest {

    private static final String USER = "alice.private";
    private static final String MFA_SESSION = "mfa-session-4711";
    private static final String INTERNAL_CAUSE = "jdbc:postgresql://db.internal:5432/contexa refused the connection";

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(AbstractMfaAuthenticationSuccessHandler.class);

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
    @DisplayName("an API client is told that the sign-in could not be completed, with the status and error code it always got")
    void theClientIsToldNoMoreThanThatItFailed() throws Exception {
        MockHttpServletResponse response = failedSignIn(true);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo("MFA_POST_SUCCESS_PIPELINE_FAILED");
        assertThat(body.path("status").asText()).isEqualTo("MFA_POST_SUCCESS_PIPELINE_FAILED");
        assertThat(body.path("message").asText()).isNotBlank();
        assertThat(body.path("path").asText()).isEqualTo("/contexa/admin/login/mfa-ott");
    }

    @Test
    @DisplayName("the body holds neither the person, the exception, the failing step nor the MFA session")
    void theBodyHoldsNoDetails() throws Exception {
        MockHttpServletResponse response = failedSignIn(true);

        String body = response.getContentAsString();
        assertThat(body).doesNotContain(USER, MFA_SESSION, INTERNAL_CAUSE, "IllegalStateException", "buildResponseData");
        Set<String> fields = new TreeSet<>();
        mapper.readTree(body).fieldNames().forEachRemaining(fields::add);
        assertThat(fields).containsExactlyInAnyOrder("timestamp", "status", "error", "message", "path");
    }

    @Test
    @DisplayName("the log keeps all of it for the operators: the person, the failing step, the exception and its text")
    void theLogKeepsTheDetails() throws Exception {
        failedSignIn(true);

        String line = logged.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(text -> text.contains("post-success pipeline failed")).findFirst().orElse("");
        assertThat(line).contains(USER, "buildResponseData", IllegalStateException.class.getName(), INTERNAL_CAUSE);
    }

    @Test
    @DisplayName("a browser request is sent to the failure page as it was")
    void aBrowserIsSentToTheFailurePage() throws Exception {
        MockHttpServletResponse response = failedSignIn(false);

        assertThat(response.getRedirectedUrl()).endsWith("?error=post_success_pipeline");
    }

    private MockHttpServletResponse failedSignIn(boolean apiRequest) throws IOException {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);
        MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
        MfaFlowUrlRegistry flowUrls = mock(MfaFlowUrlRegistry.class);
        AuthUrlProvider urls = mock(AuthUrlProvider.class);
        when(urls.getMfaFailure()).thenReturn("/mfa/failure");
        FailingHandler handler = new FailingHandler(new JsonAuthResponseWriter(mapper), mock(MfaSessionRepository.class),
                integrator, properties, applicationContext, urls, flowUrls, new IllegalStateException(INTERNAL_CAUSE));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login/mfa-ott");
        if (apiRequest) {
            request.addHeader("Accept", "application/json");
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken(USER, "pw", "ROLE_ADMIN");
        FactorContext flow = new FactorContext(MFA_SESSION, authentication,
                MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION, "mfa");

        handler.complete(request, response, authentication, flow);
        return response;
    }

    private static final class FailingHandler extends AbstractMfaAuthenticationSuccessHandler {

        private final RuntimeException failure;

        private FailingHandler(JsonAuthResponseWriter responseWriter, MfaSessionRepository sessionRepository,
                               MfaStateMachineIntegrator stateMachineIntegrator, AuthContextProperties properties,
                               ApplicationContext applicationContext, AuthUrlProvider authUrlProvider,
                               MfaFlowUrlRegistry mfaFlowUrlRegistry, RuntimeException failure) {
            super(mock(TokenService.class), responseWriter, sessionRepository, stateMachineIntegrator, properties,
                    mock(ZeroTrustEventPublisher.class), mock(ZeroTrustActionRepository.class),
                    mock(SecurityLearningService.class), applicationContext, authUrlProvider, mfaFlowUrlRegistry,
                    mock(IBlockedUserRecorder.class), mock(BlockMfaStateStore.class), mock(CentralAuditFacade.class),
                    mock(BlockingSignalBroadcaster.class));
            this.failure = failure;
        }

        private void complete(HttpServletRequest request, HttpServletResponse response, Authentication authentication,
                              FactorContext factorContext) throws IOException {
            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
        }

        @Override
        protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
            throw failure;
        }

        @Override
        protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                        Authentication authentication,
                                                        HttpServletRequest request,
                                                        HttpServletResponse response) {
            return Map.of();
        }
    }
}
