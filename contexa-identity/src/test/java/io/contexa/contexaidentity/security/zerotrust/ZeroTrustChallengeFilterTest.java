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

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import static org.mockito.Mockito.never;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
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
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import org.mockito.ArgumentCaptor;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

    @Test
    void anAnonymousVisitorIsNobodysUserAndPassesWithoutADecisionLookup() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        when(request.getRequestURI()).thenReturn("/h/public/data");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(actionRepository);
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

    /**
     * Q-5 (ownership design, 2026-11-03): under SHADOW a CHALLENGE stored earlier is not enforced; no step-up starts
     * and the request goes on.
     */
    @Test
    @DisplayName("집행이 꺼져 있으면(SHADOW) 저장된 CHALLENGE에도 요청을 통과시킨다")
    void shadow() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        setUpAuthentication();
        filter.setEnforcing(() -> false);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(challengeMfaInitializer);
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

    @Test
    @DisplayName("요청 안에서 내려진 CHALLENGE(동기 판정)는 진행 중인 절차가 없으면 새 MFA challenge flow를 시작하고 MFA 페이지를 돌려준다")
    void startsTheFlowForADecisionMadeInTheRequest() throws Exception {
        setUpChallengeAuthentication();
        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(true);
        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(challengeMfaInitializer.initializeChallengeFlow(request, response, authentication))
                .thenReturn(factorContext);
        when(authUrlProvider.getMfaSelectFactor()).thenReturn("/mfa/select-factor");

        Optional<String> mfaUrl = filter.start(request, response);

        assertThat(mfaUrl).contains("/mfa/select-factor");
        verify(challengeMfaInitializer).initializeChallengeFlow(request, response, authentication);
        verify(lockService).unlock(eq("mfa:challenge:init:testUser"), anyString());
        verify(responseWriter, never()).writeErrorResponse(any(), anyInt(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("이미 시작된 challenge 절차가 있으면 새로 시작하지 않고 그 절차의 MFA 페이지를 돌려준다")
    void reusesAFlowAlreadyStarted() throws Exception {
        setUpChallengeAuthentication();
        when(sessionRepository.getSessionId(request)).thenReturn("mfa-session-1");
        when(sessionRepository.existsSession("mfa-session-1")).thenReturn(true);
        FactorContext started = mock(FactorContext.class);
        when(started.getBooleanAttribute("challengeInitiated")).thenReturn(true);
        when(started.getCurrentState()).thenReturn(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        when(started.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(stateMachineIntegrator.loadFactorContext("mfa-session-1")).thenReturn(started);
        when(authUrlProvider.getOttRequestCodeUi()).thenReturn("/mfa/ott/request-code");

        Optional<String> mfaUrl = filter.start(request, response);

        assertThat(mfaUrl).contains("/mfa/ott/request-code");
        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
        verify(lockService, never()).tryLock(anyString(), anyString(), any());
    }

    @Test
    @DisplayName("다른 요청이 절차를 시작하는 중이거나 인증되지 않았으면 시작하지 않는다")
    void startsNothingWhenBusyOrAnonymous() throws Exception {
        assertThat(filter.start(request, response)).as("no authenticated user").isEmpty();

        setUpChallengeAuthentication();
        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(false);

        assertThat(filter.start(request, response)).as("another request is starting it").isEmpty();
        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
    }

    private void setUpAuthentication() {
        when(authentication.getName()).thenReturn("testUser");
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    @DisplayName("Without an MFA flow a CHALLENGE is refused with 401 and no procedure is opened (W1-5)")
    void challengeWithoutMfaFlowIsRefused() throws Exception {
        filter.setChallengeProcedureAvailable(false);
        when(request.getRequestURI()).thenReturn("/api/reports/export");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);

        filter.doFilter(request, response, filterChain);

        verify(responseWriter).writeErrorResponse(eq(response), eq(401), eq("ZERO_TRUST_CHALLENGE"),
                anyString(), any(), any());
        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
        verify(filterChain, never()).doFilter(request, response);
        assertThat(filter.start(request, response)).isEmpty();
    }

    /**
     * Ownership design S-1/S-2 (HOST_OWNED): the application owns sign-in, so a CHALLENGE starts no Contexa MFA flow
     * (no flow state, no session) and a browser goes to the notice that leads to the verification-only step-up.
     */
    @Test
    @DisplayName("Contexa's step-up pages are not held by a CHALLENGE")
    void stepUpPathPasses() throws Exception {
        when(request.getRequestURI()).thenReturn("/contexa/step-up/passkey/options");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(actionRepository);
    }

    @Test
    @DisplayName("HOST_OWNED: a browser goes to the notice of Contexa's step-up and no MFA flow starts")
    void hostOwnedBrowserGoesToTheStepUpNotice() throws Exception {
        filter.setHostOwnedStepUp((req, auth, key) -> false);
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);

        filter.doFilter(request, response, filterChain);

        verify(response).sendRedirect("/contexa/zero-trust/challenge-required?mfaUrl=%2Fcontexa%2Fstep-up");
        verify(filterChain, never()).doFilter(request, response);
        verifyNoInteractions(challengeMfaInitializer, sessionRepository, lockService);
    }

    @Test
    @DisplayName("HOST_OWNED: an API client gets 401 with the notice and the step-up, as under FULL")
    void hostOwnedApiClientGets401WithTheStepUp() throws Exception {
        filter.setHostOwnedStepUp((req, auth, key) -> false);
        when(request.getRequestURI()).thenReturn("/api/reports/export");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);

        filter.doFilter(request, response, filterChain);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> body = ArgumentCaptor.forClass(Map.class);
        verify(responseWriter).writeErrorResponse(eq(response), eq(401), eq("MFA_CHALLENGE_REQUIRED"),
                anyString(), any(), body.capture());
        assertThat(body.getValue()).containsEntry("mfaUrl", "/contexa/step-up")
                .containsEntry("challengeNoticeUrl",
                        "/contexa/zero-trust/challenge-required?mfaUrl=%2Fcontexa%2Fstep-up");
        verifyNoInteractions(challengeMfaInitializer, sessionRepository, lockService);
    }

    @Test
    @DisplayName("HOST_OWNED: the application's own re-authentication after the CHALLENGE lets the request on")
    void hostOwnedReauthenticationResolvesTheChallenge() throws Exception {
        filter.setHostOwnedStepUp((req, auth, key) -> "testUser".equals(key));
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    @DisplayName("HOST_OWNED: a CHALLENGE decided in the request is answered with the step-up, without a flow")
    void hostOwnedStartAnswersWithTheStepUp() {
        filter.setHostOwnedStepUp((req, auth, key) -> false);
        setUpChallengeAuthentication();

        assertThat(filter.start(request, response)).contains("/contexa/step-up");
        verifyNoInteractions(challengeMfaInitializer, sessionRepository, lockService);
    }

    @Test
    @DisplayName("Logout is never held by a CHALLENGE (W1-5)")
    void logoutPasses() throws Exception {
        when(request.getRequestURI()).thenReturn("/logout");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("a request the CHALLENGE in force stops is kept in its session (N-SES-1, G4-1)")
    void aRequestStoppedByTheChallengeIsKeptInItsSession() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        filter.setChallengeProcedureAvailable(false);
        when(request.getRequestURI()).thenReturn("/api/customers/CUS-0012");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);

        filter.doFilter(request, response, filterChain);

        verify(unanalysed).recordRequest(authentication, ZeroTrustAction.CHALLENGE);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("a request stopped while the step-up is being opened is kept in its session too (N-SES-1, G4-1)")
    void aRequestStoppedWhileTheStepUpOpensIsKeptInItsSession() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/api/customers/CUS-0012");
        setUpChallengeAuthentication();
        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(false);

        filter.doFilter(request, response, filterChain);

        verify(unanalysed).recordRequest(authentication, ZeroTrustAction.CHALLENGE);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("a request the filter lets through is not recorded by it (N-SES-1)")
    void aRequestLetThroughIsNotRecordedByTheFilter() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.ALLOW);
        setUpAuthentication();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(unanalysed, never()).recordRequest(any(), any());
    }

    @Test
    @DisplayName("A1-13: an agent under CHALLENGE is not sent into the people's MFA flow")
    void anAgentUnderChallengeWaitsForItsAccountablePartyInsteadOfMfa() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/reports");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(agentStamp());

        filter.doFilter(request, response, filterChain);

        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
        verify(filterChain, never()).doFilter(any(), any());
        verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_FORBIDDEN),
                eq(ZeroTrustChallengeFilter.AGENT_CONFIRMATION_REQUIRED), anyString(), eq("/api/reports"), any());
    }

    @Test
    @DisplayName("docs/agent A5-1: an agent acting for the user waits on its own CHALLENGE, not the user's")
    void anAgentActingForTheUserReadsItsOwnChallenge() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/reports");
        setUpChallengeAuthentication();
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(
                new DelegationStamp("testUser", "report-agent", true, null, null, null, List.of(), List.of(),
                        null, null, null, null, Map.of()));
        when(actionRepository.getCurrentAction(eq("testUser::agent::report-agent"), any()))
                .thenReturn(ZeroTrustAction.CHALLENGE);

        filter.doFilter(request, response, filterChain);

        verify(actionRepository, never()).getCurrentAction(eq("testUser"), any());
        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
        verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_FORBIDDEN),
                eq(ZeroTrustChallengeFilter.AGENT_CONFIRMATION_REQUIRED), anyString(), eq("/api/reports"), any());
    }

    @Test
    @DisplayName("A1-13: a CHALLENGE decided in an agent's request starts no MFA flow")
    void aChallengeDecidedInAnAgentsRequestStartsNoMfaFlow() throws Exception {
        setUpChallengeAuthentication();
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(agentStamp());

        assertThat(filter.start(request, response)).isEmpty();
        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
    }

    @Test
    @DisplayName("docs/agent A5-2: with the confirmation gate an agent's request goes to the gate, a person's does not")
    void anAgentsRequestMeetsTheConfirmationGateAndAPersonsTheMfaFlow() throws Exception {
        AgentConfirmationGate gate = mock(AgentConfirmationGate.class);
        when(gate.filter(any(), any(), any(), any(), any())).thenReturn(false);
        filter.setAgentConfirmationGate(gate);
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/api/reports");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(eq("testUser"), any())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(agentStamp());

        filter.doFilter(request, response, filterChain);

        verify(gate).filter(eq(request), eq(response), eq(filterChain), any(), eq(ZeroTrustAction.CHALLENGE));
        verify(challengeMfaInitializer, never()).initializeChallengeFlow(any(), any(), any());
        // The request the gate stopped under the CHALLENGE is kept in the session as one the filter stopped.
        verify(unanalysed).recordRequest(any(), eq(ZeroTrustAction.CHALLENGE));

        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(null);
        filter.doFilter(request, response, filterChain);
        verify(gate).filter(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("docs/agent F-2: the agent's subject carries the request's tenant, as the decision's subject does")
    void theAgentsSubjectCarriesTheRequestsTenant() throws Exception {
        AgentConfirmationGate gate = mock(AgentConfirmationGate.class);
        when(gate.filter(any(), any(), any(), any(), any())).thenReturn(true);
        filter.setAgentConfirmationGate(gate);
        when(request.getRequestURI()).thenReturn("/api/reports");
        setUpChallengeAuthentication();
        when(actionRepository.getCurrentAction(any(), any())).thenReturn(ZeroTrustAction.ALLOW);
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(agentStamp());
        when(request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP)).thenReturn(new AuthenticationStamp(
                "testUser", null, null, true, null, null, null, null, null, null, List.of(),
                Map.of("tenantId", "tenant-a")));

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<ZeroTrustSubject> subject = ArgumentCaptor.forClass(ZeroTrustSubject.class);
        verify(gate).filter(eq(request), eq(response), eq(filterChain), subject.capture(), eq(ZeroTrustAction.ALLOW));
        assertThat(subject.getValue().tenantId()).isEqualTo("tenant-a");
        assertThat(subject.getValue().agentId()).isEqualTo("report-bot");
    }

    @Test
    @DisplayName("CF-22: a CHALLENGE decided in an agent's request is answered by the gate, a person's is not")
    void aChallengeDecidedInAnAgentsRequestIsAnsweredByTheGate() throws Exception {
        AgentConfirmationGate gate = mock(AgentConfirmationGate.class);
        when(gate.answerDecidedChallenge(any(), any(), any())).thenReturn(true);
        filter.setAgentConfirmationGate(gate);
        setUpChallengeAuthentication();
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(agentStamp());

        assertThat(filter.answerAgentChallenge(request, response)).isTrue();
        ArgumentCaptor<ZeroTrustSubject> subject = ArgumentCaptor.forClass(ZeroTrustSubject.class);
        verify(gate).answerDecidedChallenge(eq(request), eq(response), subject.capture());
        assertThat(subject.getValue().agentId()).isEqualTo("report-bot");

        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(null);
        assertThat(filter.answerAgentChallenge(request, response)).isFalse();
        verify(gate).answerDecidedChallenge(any(), any(), any());
    }

    @Test
    @DisplayName("docs/agent A5-2: the agent polls its confirmation without meeting its own CHALLENGE")
    void theConfirmationStatusIsNotHeldByTheChallenge() {
        when(request.getRequestURI()).thenReturn("/contexa/api/agent-confirmations/c-1");
        when(request.getContextPath()).thenReturn("");

        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("the notice of a CHALLENGE loads its own scripts and styles without meeting the CHALLENGE")
    void theScreensOwnFilesAreNotHeldByTheChallenge() {
        when(request.getContextPath()).thenReturn("");
        when(request.getRequestURI()).thenReturn("/contexa/css/main.css");
        assertThat(filter.shouldNotFilter(request)).isTrue();
        when(request.getRequestURI()).thenReturn("/contexa/js/toast.js");
        assertThat(filter.shouldNotFilter(request)).isTrue();
        when(request.getRequestURI()).thenReturn("/contexa/admin/dashboard");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    private static DelegationStamp agentStamp() {
        return new DelegationStamp("report-bot", "report-bot", false, null, null, null, List.of(), List.of(),
                null, null, null, null, Map.of());
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
