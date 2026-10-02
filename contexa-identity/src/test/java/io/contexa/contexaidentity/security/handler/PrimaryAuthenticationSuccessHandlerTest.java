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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
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
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

class PrimaryAuthenticationSuccessHandlerTest {

    private static final String MFA_SESSION_ID = "mfa-session-id";

    private final Authentication authentication =
            UsernamePasswordAuthenticationToken.authenticated("user", null, List.of());

    private MfaPolicyProvider mfaPolicyProvider;
    private MfaStateMachineIntegrator stateMachineIntegrator;
    private AuthResponseWriter responseWriter;
    private FactorContext factorContext;
    private PrimaryAuthenticationSuccessHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);

        mfaPolicyProvider = mock(MfaPolicyProvider.class);
        stateMachineIntegrator = mock(MfaStateMachineIntegrator.class);
        responseWriter = mock(AuthResponseWriter.class);
        MfaSessionRepository sessionRepository = mock(MfaSessionRepository.class);

        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);

        handler = new PrimaryAuthenticationSuccessHandler(
                mfaPolicyProvider,
                null,
                responseWriter,
                properties,
                applicationContext,
                stateMachineIntegrator,
                sessionRepository,
                new AuthUrlProvider(properties),
                new MfaFlowUrlRegistry(properties),
                mock(ZeroTrustEventPublisher.class),
                mock(ZeroTrustActionRepository.class),
                mock(SecurityLearningService.class),
                mock(IBlockedUserRecorder.class),
                mock(BlockMfaStateStore.class),
                mock(CentralAuditFacade.class),
                mock(BlockingSignalBroadcaster.class),
                null);

        factorContext = new FactorContext(MFA_SESSION_ID, authentication, MfaState.NONE, "mfa");
        when(sessionRepository.getSessionId(any(HttpServletRequest.class))).thenReturn(MFA_SESSION_ID);
        when(stateMachineIntegrator.loadFactorContext(MFA_SESSION_ID)).thenReturn(factorContext);
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.PRIMARY_AUTH_SUCCESS), any(FactorContext.class),
                any(HttpServletRequest.class), anyMap())).thenReturn(true);

        request = new MockHttpServletRequest("POST", "/mfa/login");
        request.addHeader("Accept", "application/json");
        response = new MockHttpServletResponse();
        MfaPendingSessionMarker.mark(request, "mfa");
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("NO_MFA_REQUIRED decision completes authentication and removes the MFA pending marker")
    void noMfaRequiredClearsMarker() throws Exception {
        when(mfaPolicyProvider.evaluateInitialMfaRequirement(factorContext)).thenReturn(MfaDecision.noMfaRequired());

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isNull();
    }

    @Test
    @DisplayName("MFA_NOT_REQUIRED state completes authentication and removes the MFA pending marker")
    void mfaNotRequiredStateClearsMarker() throws Exception {
        MfaDecision decision = MfaDecision.builder()
                .required(false)
                .type(MfaDecision.DecisionType.CHALLENGED)
                .reason("policy evaluated without required factors")
                .build();
        when(mfaPolicyProvider.evaluateInitialMfaRequirement(factorContext)).thenReturn(decision);
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.MFA_NOT_REQUIRED), any(FactorContext.class),
                any(HttpServletRequest.class))).thenAnswer(invocation -> {
                    factorContext.changeState(MfaState.MFA_NOT_REQUIRED);
                    return true;
                });

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isNull();
    }

    @Test
    @DisplayName("Blocked decision keeps the MFA pending marker")
    void blockedDecisionKeepsMarker() throws Exception {
        when(mfaPolicyProvider.evaluateInitialMfaRequirement(factorContext)).thenReturn(MfaDecision.blocked("risk"));

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa");
        verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_FORBIDDEN),
                eq("AUTHENTICATION_BLOCKED"), anyString(), anyString(), anyMap());
    }
}
