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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.GrantedAuthority;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ZeroTrustChallengeFilterTest {

    @Mock
    private ChallengeMfaInitializer challengeMfaInitializer;
    @Mock
    private AuthResponseWriter responseWriter;
    @Mock
    private AuthUrlProvider authUrlProvider;
    @Mock
    private MfaSessionRepository sessionRepository;
    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;
    @Mock
    private DistributedLockService lockService;
    @Mock
    private MfaFlowUrlRegistry mfaFlowUrlRegistry;
    @Mock
    private ZeroTrustActionRepository actionRepository;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private Authentication authentication;

    private ZeroTrustChallengeFilter filter;

    @BeforeEach
    void setUp() {
        filter = new ZeroTrustChallengeFilter(
                challengeMfaInitializer,
                responseWriter,
                authUrlProvider,
                sessionRepository,
                stateMachineIntegrator,
                lockService,
                mfaFlowUrlRegistry,
                actionRepository
        );

        when(request.getContextPath()).thenReturn("");
        when(authUrlProvider.getMfaPageUrls()).thenReturn(Set.of(
                "/mfa/select-factor", "/mfa/failure", "/mfa/success",
                "/mfa/ott/request-code", "/mfa/ott/challenge",
                "/mfa/passkey/challenge", "/mfa/recovery/challenge"
        ));
        when(mfaFlowUrlRegistry.getAllMfaPageUrls()).thenReturn(Set.of());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("MFA API 경로는 challenge filter를 건너뛴다")
    void mfa() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/mfa/verify");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("제로트러스트 안내 경로는 challenge filter를 건너뛴다")
    void zero() throws Exception {
        when(request.getRequestURI()).thenReturn("/contexa/zero-trust/blocked");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("현재 action이 CHALLENGE가 아니면 요청을 그대로 통과시킨다")
    void pass() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.ALLOW);
        setUpAuthentication();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("미인증 상태면 요청을 그대로 통과시킨다")
    void anon() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        // No authentication in SecurityContext

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("challenge 초기화 락을 얻지 못하면 503을 반환한다")
    @SuppressWarnings("unchecked")
    void lock() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpChallengeAuthentication();
        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(false);

        filter.doFilter(request, response, filterChain);


        verify(response).setHeader("Retry-After", "3");
        verify(responseWriter).writeErrorResponse(
                eq(response),
                eq(HttpServletResponse.SC_SERVICE_UNAVAILABLE),
                eq("MFA_BUSY_RETRY"),
                eq("MFA challenge is already being initialized. Retry shortly."),
                eq("/dashboard"),
                any()
        );
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("기존 challenge 세션이 없으면 새 MFA challenge flow를 초기화한다")
    @SuppressWarnings("unchecked")
    void init() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(request.getHeader("Accept")).thenReturn("text/html");
        setUpChallengeAuthentication();

        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(true);

        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getCurrentState()).thenReturn(
                MfaState.AWAITING_FACTOR_SELECTION);
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(challengeMfaInitializer.initializeChallengeFlow(any(), any(), any()))
                .thenReturn(factorContext);
        when(authUrlProvider.getMfaSelectFactor()).thenReturn("/mfa/select-factor");

        filter.doFilter(request, response, filterChain);

        verify(challengeMfaInitializer).initializeChallengeFlow(any(), any(), any());
    }

    @Test
    @DisplayName("challenge 초기화 중 예외가 나도 분산 락은 반드시 해제한다")
    @SuppressWarnings("unchecked")
    void unl() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpChallengeAuthentication();

        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(true);

        when(challengeMfaInitializer.initializeChallengeFlow(any(), any(), any()))
                .thenThrow(new RuntimeException("Test error"));

        filter.doFilter(request, response, filterChain);

        verify(lockService).unlock(anyString(), anyString());
    }

    @Test
    @DisplayName("MFA 성공 상태(MFA_SUCCESSFUL)인 경우 세션을 정리한다")
    void successPass() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpChallengeAuthentication();

        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(sessionRepository.getSessionId(request)).thenReturn("session-123");
        when(sessionRepository.existsSession("session-123")).thenReturn(true);
        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getCurrentState()).thenReturn(MfaState.MFA_SUCCESSFUL);
        when(factorContext.getBooleanAttribute("challengeInitiated")).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContext("session-123")).thenReturn(factorContext);

        filter.doFilter(request, response, filterChain);

        verify(stateMachineIntegrator).cleanupSession(request, response);
    }

    @Test
    @DisplayName("HTML 요청이고 세션이 진행 중이면 현재 상태의 MFA 페이지로 리다이렉트한다")
    void existingSessionRedirect() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(request.getHeader("Accept")).thenReturn("text/html");
        setUpChallengeAuthentication();

        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(sessionRepository.getSessionId(request)).thenReturn("session-123");
        when(sessionRepository.existsSession("session-123")).thenReturn(true);
        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        when(factorContext.getBooleanAttribute("challengeInitiated")).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContext("session-123")).thenReturn(factorContext);
        when(authUrlProvider.getMfaSelectFactor()).thenReturn("/mfa/select-factor");

        filter.doFilter(request, response, filterChain);

        verify(response).sendRedirect(contains("/contexa/zero-trust/challenge-required"));
        verify(filterChain, never()).doFilter(any(), any());
    }

    private void setUpAuthentication() {
        when(authentication.getName()).thenReturn("testUser");
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private void setUpChallengeAuthentication() {
        when(authentication.isAuthenticated()).thenReturn(true);
        List<? extends GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority(ZeroTrustAction.CHALLENGE.getGrantedAuthority())
        );
        doReturn(authorities).when(authentication).getAuthorities();
        setUpAuthentication();
    }
}
