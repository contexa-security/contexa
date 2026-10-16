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
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * N-MFA-1: with several MFA flows, a step-up's success URL follows the settings of the step-up's own MFA flow. The final
 * success releases the state machine before the URL is chosen, so the flow comes from the factor context the handler
 * was given; only a success without one falls back to the first MFA flow.
 */
class MfaStepUpFlowSelectionTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aStepUpOfTheSecondFlowGoesToTheSecondFlowsSuccessUrl() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/mfa/ott/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");
        FactorContext factorContext = new FactorContext("mfa-session-2", authentication, MfaState.NONE, "mfa_admin");

        handler(flow("mfa", "/first"), flow("mfa_admin", "/second"))
                .complete(request, response, authentication, factorContext);

        assertThat(response.getRedirectedUrl()).isEqualTo("/second");
    }

    @Test
    void aSuccessWithoutAFactorContextStillGoesToTheFirstMfaFlowsSuccessUrl() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");

        handler(flow("mfa", "/first"), flow("mfa_admin", "/second"))
                .complete(request, response, authentication, null);

        assertThat(response.getRedirectedUrl()).isEqualTo("/first");
    }

    private static FlowHandler handler(AuthenticationFlowConfig... flows) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(mock(AISessionSecurityContextRepository.class));
        PlatformConfig platformConfig = mock(PlatformConfig.class);
        when(platformConfig.getFlows()).thenReturn(List.of(flows));
        when(applicationContext.getBean(PlatformConfig.class)).thenReturn(platformConfig);
        return new FlowHandler(applicationContext, properties);
    }

    private static AuthenticationFlowConfig flow(String typeName, String successUrl) {
        FormOptions form = mock(FormOptions.class);
        when(form.getDefaultSuccessUrl()).thenReturn(successUrl);
        when(form.isAlwaysUseDefaultSuccessUrl()).thenReturn(true);
        PrimaryAuthenticationOptions primary = mock(PrimaryAuthenticationOptions.class);
        when(primary.getFormOptions()).thenReturn(form);
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        when(flow.getPrimaryAuthenticationOptions()).thenReturn(primary);
        return flow;
    }

    /** The handler as it is, its success URL included; the state machine it releases holds nothing any more. */
    private static final class FlowHandler extends AbstractMfaAuthenticationSuccessHandler {

        private FlowHandler(ApplicationContext applicationContext, AuthContextProperties properties) {
            super(null, mock(AuthResponseWriter.class), mock(MfaSessionRepository.class),
                    mock(MfaStateMachineIntegrator.class), properties, mock(ZeroTrustEventPublisher.class),
                    mock(ZeroTrustActionRepository.class), mock(SecurityLearningService.class), applicationContext,
                    mock(AuthUrlProvider.class), mock(MfaFlowUrlRegistry.class), mock(IBlockedUserRecorder.class),
                    mock(BlockMfaStateStore.class), mock(CentralAuditFacade.class), mock(BlockingSignalBroadcaster.class));
        }

        private void complete(HttpServletRequest request, HttpServletResponse response, Authentication authentication,
                              FactorContext factorContext) throws IOException {
            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
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
