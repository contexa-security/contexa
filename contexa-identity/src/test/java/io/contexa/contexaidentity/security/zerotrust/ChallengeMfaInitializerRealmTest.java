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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaAdminRealm;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-13 of docs/agent/운영모드-정상화-구현계획.md: the flow of Contexa's administrators lies under the console's prefix and joins
 * an application's own flows. A step-up names it for a request of the console only; any other request, also one of the
 * application's users under that prefix, is never put into it by a fallback.
 */
@DisplayName("CHALLENGE의 흐름 선택은 콘솔 요청이 아니면 관리 흐름을 고르지 않는다(R-13)")
class ChallengeMfaInitializerRealmTest {

    private final MfaStateMachineIntegrator stateMachine = mock(MfaStateMachineIntegrator.class);
    private final MfaPolicyProvider policy = mock(MfaPolicyProvider.class);

    @Test
    @DisplayName("앱 흐름에 MFA 흐름이 없을 때 앱 요청의 흐름은 관리 흐름이 아니다")
    void anApplicationsRequestIsNotPutIntoTheAdministratorsFlow() {
        assertThat(chosenFlow(new MockHttpServletRequest("GET", "/h/reports")))
                .isNotEqualTo(ContexaSignInRealm.adminFlowTypeName());
    }

    @Test
    @DisplayName("관리 영역 접두어 아래의 앱 사용자 경로(콘솔이 아님)도 관리 흐름을 고르지 않는다")
    void theUsersOwnPathUnderTheConsolePrefixIsNotPutIntoTheAdministratorsFlow() {
        assertThat(chosenFlow(new MockHttpServletRequest("GET", "/contexa/admin/api/aiam/zero-trust/decisions")))
                .isNotEqualTo(ContexaSignInRealm.adminFlowTypeName());
    }

    @Test
    @DisplayName("콘솔 요청은 지금처럼 관리 흐름을 고른다")
    void aRequestOfTheConsoleIsPutIntoTheAdministratorsFlow() {
        MockHttpServletRequest console = new MockHttpServletRequest("GET", "/contexa/admin/users");
        ConsoleSession.mark(console);

        assertThat(chosenFlow(console)).isEqualTo(ContexaSignInRealm.adminFlowTypeName());
    }

    /** The flow the step-up of the request starts in: the context the state machine is initialized with names it. */
    private String chosenFlow(MockHttpServletRequest request) {
        PlatformConfig config = PlatformConfig.builder().addFlow(flow("form_flow", null))
                .addFlow(flow(ContexaSignInRealm.adminFlowTypeName(), ContexaAdminRealm.URL_PREFIX)).build();
        when(policy.evaluateInitialMfaRequirement(any())).thenReturn(MfaDecision.builder().required(true).build());
        ChallengeMfaInitializer initializer = new ChallengeMfaInitializer(mock(MfaSessionRepository.class), stateMachine,
                policy, config);

        assertThatThrownBy(() -> initializer.initializeChallengeFlow(request, new MockHttpServletResponse(),
                UsernamePasswordAuthenticationToken.authenticated("testUser", null, List.of())))
                .as("the state machine of this test sends no event")
                .isInstanceOf(ChallengeMfaInitializer.ChallengeMfaInitializationException.class);
        ArgumentCaptor<FactorContext> context = ArgumentCaptor.forClass(FactorContext.class);
        verify(stateMachine).initializeStateMachine(context.capture(), any(), any());
        return context.getValue().getFlowTypeName();
    }

    private static AuthenticationFlowConfig flow(String typeName, String urlPrefix) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        when(flow.getUrlPrefix()).thenReturn(urlPrefix);
        return flow;
    }
}
