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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.ZeroTrustChallengeConfigurer;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-13 of docs/agent/운영모드-정상화-구현계획.md: the flow of Contexa's administrators joins an application's own flows,
 * and it is a procedure for the console's requests only. A user of the application under a CHALLENGE gets the answer they
 * got before that flow joined: without an MFA flow of the application's, the refusal without a procedure; an administrator
 * on the console still steps up in the flow of the administrators.
 */
@DisplayName("CHALLENGE의 추가 인증 절차는 요청의 영역(앱 사용자 / Contexa 콘솔)으로 정한다(R-13)")
class AdminRealmChallengeProcedureTest {

    private final ChallengeMfaInitializer initializer = mock(ChallengeMfaInitializer.class);
    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final AuthUrlProvider authUrlProvider = mock(AuthUrlProvider.class);
    private final MfaSessionRepository sessions = mock(MfaSessionRepository.class);
    private final MfaStateMachineIntegrator stateMachine = mock(MfaStateMachineIntegrator.class);
    private final DistributedLockService locks = mock(DistributedLockService.class);
    private final MfaFlowUrlRegistry flowUrls = mock(MfaFlowUrlRegistry.class);
    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final FilterChain chain = mock(FilterChain.class);

    private final ZeroTrustChallengeFilter filter = new ZeroTrustChallengeFilter(initializer, responseWriter, authUrlProvider,
            sessions, stateMachine, locks, flowUrls, actions);

    @BeforeEach
    void underAChallenge() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "testUser", null, AuthorityUtils.createAuthorityList(ZeroTrustAction.CHALLENGE.getGrantedAuthority())));
        when(actions.getCurrentAction(anyString(), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(locks.tryLock(anyString(), anyString(), any())).thenReturn(true);
        when(authUrlProvider.getMfaPageUrls()).thenReturn(Set.of());
        when(authUrlProvider.getMfaSelectFactor()).thenReturn("/mfa/select-factor");
        when(flowUrls.getAllMfaPageUrls()).thenReturn(Set.of());
        FactorContext started = mock(FactorContext.class);
        when(started.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(initializer.initializeChallengeFlow(any(), any(), any())).thenReturn(started);
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("앱 흐름에 MFA 흐름이 없으면 앱 사용자의 CHALLENGE는 관리 흐름으로 가지 않고 절차 없는 거절 화면으로 간다")
    void theApplicationsUserIsNotSteppedUpInTheAdministratorsFlow() throws Exception {
        configure(flow("form_flow"), adminFlow());
        MockHttpServletRequest request = page("/h/reports");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/zero-trust/challenge-required?stepUp=none");
        verify(initializer, never()).initializeChallengeFlow(any(), any(), any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("요청 안에서 내린 CHALLENGE도 앱 사용자에게는 관리 흐름의 절차를 시작하지 않는다")
    void aChallengeDecidedInTheRequestStartsNoProcedureForTheApplicationsUser() {
        configure(flow("form_flow"), adminFlow());

        assertThat(filter.start(page("/h/reports"), new MockHttpServletResponse())).isEmpty();
        verify(initializer, never()).initializeChallengeFlow(any(), any(), any());
    }

    @Test
    @DisplayName("관리자의 콘솔 요청은 지금처럼 관리 흐름으로 추가 인증한다")
    void theAdministratorOnTheConsoleStepsUpInTheAdministratorsFlow() throws Exception {
        configure(flow("form_flow"), adminFlow());
        MockHttpServletRequest request = page("/contexa/admin/users");
        ConsoleSession.mark(request);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(initializer).initializeChallengeFlow(any(), any(), any());
    }

    @Test
    @DisplayName("앱에 MFA 흐름이 있으면 앱 사용자는 지금처럼 그 흐름으로 추가 인증한다")
    void theApplicationsUserStepsUpInTheApplicationsFlow() throws Exception {
        configure(flow("mfa"), adminFlow());

        filter.doFilter(page("/h/reports"), new MockHttpServletResponse(), chain);

        verify(initializer).initializeChallengeFlow(any(), any(), any());
    }

    private void configure(AuthenticationFlowConfig... flows) {
        PlatformConfig.Builder config = PlatformConfig.builder();
        for (AuthenticationFlowConfig flow : flows) {
            config.addFlow(flow);
        }
        new ZeroTrustChallengeConfigurer(filter).init(null, config.build());
    }

    private static AuthenticationFlowConfig adminFlow() {
        return flow(ContexaSignInRealm.adminFlowTypeName());
    }

    private static AuthenticationFlowConfig flow(String typeName) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        return flow;
    }

    private static MockHttpServletRequest page(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.addHeader("Accept", "text/html");
        return request;
    }
}
