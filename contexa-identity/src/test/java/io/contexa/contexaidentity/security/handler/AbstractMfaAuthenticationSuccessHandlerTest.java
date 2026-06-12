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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

class AbstractMfaAuthenticationSuccessHandlerTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("SESSION MFA completion persists final authentication in AISessionSecurityContextRepository")
    void save() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);

        AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
        MfaSessionRepository sessionRepository = mock(MfaSessionRepository.class);
        MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
        ZeroTrustEventPublisher eventPublisher = mock(ZeroTrustEventPublisher.class);
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        SecurityLearningService learningService = mock(SecurityLearningService.class);
        AuthUrlProvider authUrlProvider = mock(AuthUrlProvider.class);
        MfaFlowUrlRegistry flowUrlRegistry = mock(MfaFlowUrlRegistry.class);
        IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
        BlockMfaStateStore blockMfaStateStore = mock(BlockMfaStateStore.class);
        CentralAuditFacade centralAuditFacade = mock(CentralAuditFacade.class);
        BlockingSignalBroadcaster blockingSignalBroadcaster = mock(BlockingSignalBroadcaster.class);
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);

        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);

        TestHandler handler = new TestHandler(
                null,
                responseWriter,
                sessionRepository,
                integrator,
                properties,
                eventPublisher,
                actionRepository,
                learningService,
                applicationContext,
                authUrlProvider,
                flowUrlRegistry,
                blockedUserRecorder,
                blockMfaStateStore,
                centralAuditFacade,
                blockingSignalBroadcaster,
                false
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");

        handler.complete(request, response, authentication);

        ArgumentCaptor<SecurityContext> contextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
        verify(aiRepository).saveContext(contextCaptor.capture(), eq(request), eq(response));
        assertThat(contextCaptor.getValue().getAuthentication().getName()).isEqualTo("admin");
    }

    @Test
    @DisplayName("Returns structured error response when post-success pipeline fails")
    void returnsStructuredErrorResponseWhenPostSuccessPipelineFails() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);

        AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
        MfaSessionRepository sessionRepository = mock(MfaSessionRepository.class);
        MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
        ZeroTrustEventPublisher eventPublisher = mock(ZeroTrustEventPublisher.class);
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        SecurityLearningService learningService = mock(SecurityLearningService.class);
        AuthUrlProvider authUrlProvider = mock(AuthUrlProvider.class);
        MfaFlowUrlRegistry flowUrlRegistry = mock(MfaFlowUrlRegistry.class);
        IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
        BlockMfaStateStore blockMfaStateStore = mock(BlockMfaStateStore.class);
        CentralAuditFacade centralAuditFacade = mock(CentralAuditFacade.class);
        BlockingSignalBroadcaster blockingSignalBroadcaster = mock(BlockingSignalBroadcaster.class);
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);

        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);

        TestHandler handler = new TestHandler(
                null,
                responseWriter,
                sessionRepository,
                integrator,
                properties,
                eventPublisher,
                actionRepository,
                learningService,
                applicationContext,
                authUrlProvider,
                flowUrlRegistry,
                blockedUserRecorder,
                blockMfaStateStore,
                centralAuditFacade,
                blockingSignalBroadcaster,
                true
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");

        handler.complete(request, response, authentication);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> detailCaptor = ArgumentCaptor.forClass((Class) Map.class);
        verify(responseWriter).writeErrorResponse(
                eq(response),
                eq(HttpServletResponse.SC_INTERNAL_SERVER_ERROR),
                eq("MFA_POST_SUCCESS_PIPELINE_FAILED"),
                contains("buildResponseData"),
                eq("/admin/login/mfa-ott"),
                detailCaptor.capture());
        assertThat(detailCaptor.getValue())
                .containsEntry("status", "MFA_POST_SUCCESS_PIPELINE_FAILED")
                .containsEntry("failedStage", "buildResponseData")
                .containsEntry("userId", "admin");
    }

    private static final class TestHandler extends AbstractMfaAuthenticationSuccessHandler {

        private final boolean failOnBuildResponse;

        private TestHandler(TokenService tokenService,
                            AuthResponseWriter responseWriter,
                            MfaSessionRepository sessionRepository,
                            MfaStateMachineIntegrator stateMachineIntegrator,
                            AuthContextProperties authContextProperties,
                            ZeroTrustEventPublisher zeroTrustEventPublisher,
                            ZeroTrustActionRepository actionRedisRepository,
                            SecurityLearningService securityLearningService,
                            ApplicationContext applicationContext,
                            AuthUrlProvider authUrlProvider,
                            MfaFlowUrlRegistry mfaFlowUrlRegistry,
                            IBlockedUserRecorder blockedUserRecorder,
                            BlockMfaStateStore blockMfaStateStore,
                            CentralAuditFacade centralAuditFacade,
                            BlockingSignalBroadcaster blockingSignalBroadcaster,
                            boolean failOnBuildResponse) {
            super(tokenService, responseWriter, sessionRepository, stateMachineIntegrator, authContextProperties,
                    zeroTrustEventPublisher, actionRedisRepository, securityLearningService, applicationContext,
                    authUrlProvider, mfaFlowUrlRegistry, blockedUserRecorder, blockMfaStateStore,
                    centralAuditFacade, blockingSignalBroadcaster);
            this.failOnBuildResponse = failOnBuildResponse;
        }

        private void complete(HttpServletRequest request,
                              HttpServletResponse response,
                              Authentication authentication) throws IOException {
            handleFinalAuthenticationSuccess(request, response, authentication, null);
        }

        @Override
        protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
            if (failOnBuildResponse) {
                throw new IllegalStateException("boom");
            }
            return "/admin";
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
