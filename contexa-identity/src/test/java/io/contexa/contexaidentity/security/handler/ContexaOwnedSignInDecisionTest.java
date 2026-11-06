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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Where Contexa owns the sign-in, a completed sign-in goes to the engine as the application's own sign-in does where the
 * application owns it: once, before the response leaves, so a sign-in that looks wrong is decided and the next request
 * meets the decision. A step-up that answers a CHALLENGE or a BLOCK is no sign-in.
 */
class ContexaOwnedSignInDecisionTest {

    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final Authentication admin = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static FactorContext completed(boolean challengeFlow) {
        FactorContext factorContext = new FactorContext("mfa-session-1",
                new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"), MfaState.NONE, "mfa");
        factorContext.changeState(MfaState.MFA_SUCCESSFUL);
        if (challengeFlow) {
            factorContext.setAttribute("challengeInitiated", true);
        }
        return factorContext;
    }

    private static MockHttpServletRequest browserRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        request.setSession(new MockHttpSession(null, "session-1"));
        return request;
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> signIn() {
        return ArgumentCaptor.forClass(Map.class);
    }

    @Test
    @DisplayName("a completed MFA sign-in goes to the engine once, and is audited as before")
    void aCompletedMfaSignInIsDecided() throws Exception {
        MockHttpServletRequest request = browserRequest();

        handler(StateType.SESSION).complete(request, new MockHttpServletResponse(), admin, completed(false));

        ArgumentCaptor<Map<String, Object>> facts = signIn();
        verify(publisher).publishAuthenticationSuccess(eq(admin), eq(request), facts.capture());
        assertThat(facts.getValue()).containsEntry("authenticationType", "MFA").containsEntry("mfaCompleted", true);
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getEventCategory()).isEqualTo(AuditEventCategory.AUTHENTICATION_SUCCESS);
    }

    @Test
    @DisplayName("a sign-in that needed no second step goes to the engine too")
    void aSignInWithoutASecondStepIsDecided() throws Exception {
        FactorContext notRequired = new FactorContext("mfa-session-2", admin, MfaState.NONE, "mfa");
        notRequired.changeState(MfaState.MFA_NOT_REQUIRED);

        handler(StateType.SESSION).complete(browserRequest(), new MockHttpServletResponse(), admin, notRequired);

        ArgumentCaptor<Map<String, Object>> facts = signIn();
        verify(publisher).publishAuthenticationSuccess(eq(admin), any(), facts.capture());
        assertThat(facts.getValue()).containsEntry("authenticationType", "PRIMARY");
    }

    @Test
    @DisplayName("a sign-in on the token state goes to the engine")
    void aTokenSignInIsDecided() throws Exception {
        handler(StateType.OAUTH2).complete(browserRequest(), new MockHttpServletResponse(), admin, completed(false));

        verify(publisher).publishAuthenticationSuccess(eq(admin), any(), any());
    }

    @Test
    @DisplayName("it goes before the response leaves, so the next request meets what it brought")
    void itGoesBeforeTheResponse() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        List<Boolean> committedWhenPublished = new ArrayList<>();
        doAnswer(call -> {
            committedWhenPublished.add(response.isCommitted());
            return null;
        }).when(publisher).publishAuthenticationSuccess(any(), any(), any());

        handler(StateType.SESSION).complete(browserRequest(), response, admin, completed(false));

        assertThat(committedWhenPublished).containsExactly(false);
        assertThat(response.isCommitted()).isTrue();
    }

    @Test
    @DisplayName("the step-up that answers a CHALLENGE is no sign-in")
    void aStepUpIsNoSignIn() throws Exception {
        handler(StateType.SESSION).complete(browserRequest(), new MockHttpServletResponse(), admin, completed(true));

        verify(publisher, never()).publishAuthenticationSuccess(any(), any(), any());
    }

    @Test
    @DisplayName("the verification that releases a BLOCK is no sign-in")
    void aBlockVerificationIsNoSignIn() throws Exception {
        FactorContext blockMfa = completed(false);
        blockMfa.setAttribute(ZeroTrustAccessControlFilter.BLOCK_MFA_FLOW_ATTRIBUTE, true);

        handler(StateType.SESSION).complete(browserRequest(), new MockHttpServletResponse(), admin, blockMfa);

        verify(publisher, never()).publishAuthenticationSuccess(any(), any(), any());
    }

    @Test
    @DisplayName("an engine that cannot take the sign-in does not stop it")
    void anEngineThatFailsDoesNotStopTheSignIn() throws Exception {
        doThrow(new IllegalStateException("no engine")).when(publisher).publishAuthenticationSuccess(any(), any(), any());
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatCode(() -> handler(StateType.SESSION).complete(browserRequest(), response, admin, completed(false)))
                .doesNotThrowAnyException();

        assertThat(response.getRedirectedUrl()).isEqualTo("/admin");
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
    }

    private TestHandler handler(StateType stateType) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(stateType);
        TokenService tokenService = mock(TokenService.class);
        when(tokenService.createTokenPair(any(), any(), any(), any()))
                .thenReturn(TokenPair.builder().accessToken("access").refreshToken("refresh").build());
        when(tokenService.prepareTokensForTransport("access", "refresh"))
                .thenReturn(TokenTransportResult.builder().body(Map.of("accessToken", "access")).build());
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);
        when(applicationContext.getBean(SecurityContextDataStore.class)).thenReturn(mock(SecurityContextDataStore.class));
        return new TestHandler(tokenService, mock(AuthResponseWriter.class), mock(MfaSessionRepository.class),
                mock(MfaStateMachineIntegrator.class), properties, publisher, mock(ZeroTrustActionRepository.class),
                mock(SecurityLearningService.class), applicationContext, mock(AuthUrlProvider.class),
                mock(MfaFlowUrlRegistry.class), mock(IBlockedUserRecorder.class), mock(BlockMfaStateStore.class), audit,
                mock(BlockingSignalBroadcaster.class));
    }

    private static final class TestHandler extends AbstractMfaAuthenticationSuccessHandler {

        private TestHandler(TokenService tokenService, AuthResponseWriter responseWriter,
                            MfaSessionRepository sessionRepository, MfaStateMachineIntegrator stateMachineIntegrator,
                            AuthContextProperties authContextProperties, ZeroTrustEventPublisher zeroTrustEventPublisher,
                            ZeroTrustActionRepository actionRedisRepository,
                            SecurityLearningService securityLearningService, ApplicationContext applicationContext,
                            AuthUrlProvider authUrlProvider, MfaFlowUrlRegistry mfaFlowUrlRegistry,
                            IBlockedUserRecorder blockedUserRecorder, BlockMfaStateStore blockMfaStateStore,
                            CentralAuditFacade centralAuditFacade, BlockingSignalBroadcaster blockingSignalBroadcaster) {
            super(tokenService, responseWriter, sessionRepository, stateMachineIntegrator, authContextProperties,
                    zeroTrustEventPublisher, actionRedisRepository, securityLearningService, applicationContext,
                    authUrlProvider, mfaFlowUrlRegistry, blockedUserRecorder, blockMfaStateStore,
                    centralAuditFacade, blockingSignalBroadcaster);
        }

        private void complete(HttpServletRequest request, HttpServletResponse response, Authentication authentication,
                              FactorContext factorContext) throws IOException {
            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
        }

        @Override
        protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
            return "/admin";
        }
    }
}
