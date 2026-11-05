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
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.blocking.BlockableResponseWrapper;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ZeroTrustAccessControlFilterTest {

    @Mock
    private ZeroTrustActionRepository actionRedisRepository;
    @Mock
    private AuthResponseWriter responseWriter;
    @Mock
    private IBlockedUserRecorder blockedUserRecorder;
    @Mock
    private ChallengeMfaInitializer challengeMfaInitializer;
    @Mock
    private AuthUrlProvider authUrlProvider;
    @Mock
    private BlockingSignalBroadcaster blockingSignalBroadcaster;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private Authentication authentication;

    private ZeroTrustAccessControlFilter filter;

    private static final String TEST_CONTEXT_BINDING_HASH = "abc123def456";

    @BeforeEach
    void setUp() {
        filter = new ZeroTrustAccessControlFilter(
                actionRedisRepository,
                responseWriter,
                blockedUserRecorder,
                challengeMfaInitializer,
                authUrlProvider,
                blockingSignalBroadcaster,
                2
        );

        when(request.getContextPath()).thenReturn("");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("testUser");
        when(authentication.getAuthorities()).thenReturn(List.of());
    }

    @Test
    void anAnonymousVisitorIsNobodysUserAndPassesWithoutADecisionLookup() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        when(request.getRequestURI()).thenReturn("/h/public/data");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(actionRedisRepository);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldNotFilter_logoutPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/logout");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(actionRedisRepository);
    }

    @Test
    void shouldNotFilter_zeroTrustPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/contexa/zero-trust/blocked");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(actionRedisRepository);
    }

    @Test
    void shouldPassThrough_whenNotAuthenticated() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        // No authentication set in SecurityContext

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldPassThrough_whenActionIsAllow() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.ALLOW);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    /**
     * Q-5 (ownership design, 2026-11-03): under SHADOW nothing is stopped, in either ownership. A restriction stored
     * earlier (an ENFORCE period, an administrator's block) stays stored but is not enforced; the request goes on and
     * the decision store is not read.
     */
    @Test
    void shouldPassThrough_whenEnforcementIsOff() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        setUpAuthentication();
        filter.setEnforcing(() -> false);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(response, never()).sendRedirect(any());
        verifyNoInteractions(actionRedisRepository);
    }

    /**
     * Ownership browser check 2026-11-03: a signed-in user under a BLOCK got the screen's own script answered with the
     * redirect to the screen, so the release request of the block screen never ran (FULL and HOST_OWNED alike).
     */
    @Test
    void shouldNotFilter_theScreensOwnFiles() throws Exception {
        setUpAuthentication();
        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            for (String path : new String[] {"/contexa/js/zero-trust/blocked.js", "/contexa/css/main.css",
                    "/contexa/img/logo.png"}) {
                when(request.getRequestURI()).thenReturn(path);

                filter.doFilter(request, response, filterChain);
            }

            verify(filterChain, times(3)).doFilter(request, response);
            verify(response, never()).sendRedirect(anyString());
            verify(response, never()).setStatus(anyInt());
        }
    }

    @Test
    void shouldNotFilter_stepUpPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/contexa/step-up");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(actionRedisRepository);
    }

    /** PR-65: a path that only starts like one of Contexa's is the application's, and the decision reaches it. */
    @ParameterizedTest
    @ValueSource(strings = {"/logout-report", "/logoutreport", "/logout.json", "/logout/report",
            "/contexa/zero-trust-export", "/contexa/step-up-history",
            "/contexa/api/aiam/zero-trustee", "/contexa/api/aiam/sse/zero-trustee",
            "/contexa/admin/api/aiam/zero-trust-audit", "/contexa/admin/api/aiam/sse/zero-trust-audit",
            "/.well-known/customer-export"})
    void anApplicationPathThatOnlyStartsLikeContexasMeetsTheDecision(String path) {
        when(request.getRequestURI()).thenReturn(path);

        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    /** PR-65: what the container resolves to another path never counts as Contexa's, whatever it starts with. */
    @ParameterizedTest
    @ValueSource(strings = {"/logout;x=1", "/logout/..;/owners/1", "/logout/../owners/1", "/logout/%2e%2e/owners/1",
            "/logout%2f..%2fowners%2f1", "/logout\\..\\owners\\1", "/logout//",
            "/contexa/zero-trust/..;/..;/owners/1", "/contexa/zero-trust/../../owners/1",
            "/contexa/zero-trust;x=1/blocked", "/contexa/zero-trust/%2e%2e/%2e%2e/owners/1",
            "/contexa/step-up/..;/..;/owners/1", "/contexa/admin/api/aiam/zero-trust/..;/..;/..;/..;/..;/owners/1",
            "/.well-known/webauthn/..;/..;/owners/1", "/.well-known/%2e%2e/owners/1"})
    void aWayOutOfContexasPathsMeetsTheDecision(String path) {
        when(request.getRequestURI()).thenReturn(path);

        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/logout", "/logout/", "/contexa/zero-trust", "/contexa/zero-trust/blocked",
            "/contexa/zero-trust/challenge-required", "/contexa/step-up", "/contexa/step-up/passkey/options",
            "/contexa/api/aiam/zero-trust/status", "/contexa/api/aiam/sse/zero-trust/stream",
            "/contexa/admin/api/aiam/zero-trust/unblock-request", "/contexa/admin/api/aiam/sse/zero-trust/stream",
            "/.well-known/authzen-configuration", "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/tenant",
            "/.well-known/oauth-protected-resource", "/.well-known/webauthn"})
    void contexasOwnPathsStayOutOfTheDecision(String path) {
        when(request.getRequestURI()).thenReturn(path);

        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void theContextPathDoesNotChangeWhatIsContexas() {
        when(request.getContextPath()).thenReturn("/app");
        when(request.getRequestURI()).thenReturn("/app/logout");
        assertThat(filter.shouldNotFilter(request)).isTrue();

        when(request.getRequestURI()).thenReturn("/app/logout-report");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    /** PR-65, measured: a user under a BLOCK got the data of the application's /logout-report. */
    @Test
    void aBlockedUserDoesNotReachAnApplicationPathNamedLikeLogout() throws Exception {
        when(request.getRequestURI()).thenReturn("/logout-report");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(eq(request), eq(response));
            verify(response).sendRedirect("/contexa/zero-trust/blocked");
        }
    }

    /** PR-65: while a BLOCK waits for its MFA, the sign-in Contexa runs is open and the application's lookalikes are not. */
    @ParameterizedTest
    @ValueSource(strings = {"/mfa/reports", "/api/mfa/transfer", "/webauthn/devices", "/login/mfa-report",
            "/mfa/select-factor-audit", "/mfa/select-factor/..;/..;/owners/1"})
    void underAPendingBlockMfaAnApplicationPathStaysStopped(String path) throws Exception {
        when(authUrlProvider.getAllMfaRelatedUrls()).thenReturn(Set.of("/mfa/select-factor", "/webauthn/register"));
        when(request.getRequestURI()).thenReturn(path);
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);
            when(actionRedisRepository.getBlockMfaFailCount("testUser")).thenReturn(0L);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/mfa/select-factor", "/webauthn/register", "/webauthn/register/credential-id", "/mfa/login",
            "/contexa/admin/api/mfa/config"})
    void underAPendingBlockMfaTheSignInContexaRunsStaysOpen(String path) throws Exception {
        when(authUrlProvider.getAllMfaRelatedUrls()).thenReturn(Set.of("/mfa/select-factor", "/webauthn/register"));
        when(authUrlProvider.getMfaInProgressUrls()).thenReturn(Set.of("/mfa/login"));
        when(request.getRequestURI()).thenReturn(path);
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);
            when(actionRedisRepository.getBlockMfaFailCount("testUser")).thenReturn(0L);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    /** "/api/mfa/" let a user under a BLOCK through to the application's own path of that name. */
    @Test
    void hostOwnedApplicationPathThatLooksLikeMfaStaysBlocked() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/mfa/transfer");
        setUpAuthentication();
        filter.setHostOwnedStepUp((req, auth, key) -> false);

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);
            when(actionRedisRepository.getBlockMfaFailCount("testUser")).thenReturn(0L);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    /**
     * Ownership design S-1/S-2 (HOST_OWNED): a BLOCK an administrator let the user release by MFA goes to Contexa's
     * verification-only step-up; no Contexa MFA flow starts.
     */
    @Test
    void hostOwnedBlockReleasedByMfaGoesToTheStepUp() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        setUpAuthentication();
        filter.setHostOwnedStepUp((req, auth, key) -> false);

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);
            when(actionRedisRepository.getBlockMfaFailCount("testUser")).thenReturn(0L);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(eq(request), eq(response));
            verify(response).sendRedirect("/contexa/step-up?purpose=block");
            verifyNoInteractions(challengeMfaInitializer);
        }
    }

    @Test
    void shouldHandleBlock_whenBlockAction() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(false);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(eq(request), eq(response));
            verify(response).sendRedirect("/contexa/zero-trust/blocked");
        }
    }

    @Test
    void anAgentActingForTheUserIsStoppedByItsOwnBlockWithoutTheUsersMfa() throws Exception {
        // docs/agent A5-1: the agent's decision is read under its own key; its block asks no factor of anyone.
        when(request.getRequestURI()).thenReturn("/api/projects/HX-310/exports");
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(delegatedAgentStamp());
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser::agent::report-agent", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(any(), any());
            verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_FORBIDDEN),
                    eq(ZeroTrustAccessControlFilter.AGENT_BLOCKED), anyString(), eq("/api/projects/HX-310/exports"),
                    any());
            verify(actionRedisRepository, never()).isBlockMfaPending(anyString());
            verify(actionRedisRepository, never()).getCurrentAction(eq("testUser"), any());
        }
    }

    @Test
    void anAgentsEscalationIsPromotedUnderItsOwnKeyAndRecordsNoBlockedPerson() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/projects/HX-310/exports");
        when(request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)).thenReturn(delegatedAgentStamp());
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser::agent::report-agent", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.ESCALATE);

            filter.doFilter(request, response, filterChain);

            verify(actionRedisRepository).saveAction(eq("testUser::agent::report-agent"), eq(ZeroTrustAction.BLOCK),
                    any());
            verify(actionRedisRepository).setBlockedFlag("testUser::agent::report-agent");
            verify(actionRedisRepository, never()).setBlockedFlag("testUser");
            verifyNoInteractions(blockedUserRecorder);
            verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_FORBIDDEN),
                    eq(ZeroTrustAccessControlFilter.AGENT_BLOCKED), anyString(), anyString(), any());
        }
    }

    private static DelegationStamp delegatedAgentStamp() {
        return new DelegationStamp("testUser", "report-agent", true, null, null, null, List.of(), List.of(),
                null, null, null, null, Map.of());
    }

    @Test
    void shouldHandleEscalate_withHashAction() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        when(request.getHeader("Accept")).thenReturn("text/html");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.ESCALATE);
            when(actionRedisRepository.getActionFromHash("testUser"))
                    .thenReturn(ZeroTrustAction.ESCALATE);

            filter.doFilter(request, response, filterChain);

            verify(actionRedisRepository).setEscalateRetry(eq("testUser"), any());
            verify(response).setHeader(eq("Retry-After"), eq("30"));
            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    @Test
    void shouldPromoteEscalateToBlock_whenNoHashAndNoRetry() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("User-Agent")).thenReturn("TestAgent");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.ESCALATE);
            when(actionRedisRepository.getActionFromHash("testUser")).thenReturn(null);
            when(actionRedisRepository.hasEscalateRetry("testUser")).thenReturn(false);

            filter.doFilter(request, response, filterChain);

            verify(actionRedisRepository).saveAction(eq("testUser"), eq(ZeroTrustAction.BLOCK), any());
            verify(actionRedisRepository).setBlockedFlag("testUser");
            verify(response).sendRedirect("/contexa/zero-trust/blocked");
        }
    }

    @Test
    void shouldHandlePendingAnalysis_withBlockableWrapper() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(eq(request), any(BlockableResponseWrapper.class));
        }
    }

    @Test
    void shouldPassThrough_whenBlockMfaIsPending() throws Exception {
        when(authUrlProvider.getAllMfaRelatedUrls()).thenReturn(Set.of("/mfa/select-factor"));
        when(request.getRequestURI()).thenReturn("/mfa/select-factor");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(response, never()).sendRedirect(anyString());
        }
    }

    @Test
    void shouldBlockImmediately_whenBlockRetryLimitExceeded() throws Exception {
        when(request.getRequestURI()).thenReturn("/some/path");
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));
        setUpAuthentication();

        // 락 해제 재시도 횟수 초과 설정
        ZeroTrustAccessControlFilter customFilter = new ZeroTrustAccessControlFilter(
                actionRedisRepository,
                responseWriter,
                blockedUserRecorder,
                challengeMfaInitializer,
                authUrlProvider,
                blockingSignalBroadcaster,
                0 // 시도 가능 횟수 0으로 제한
        );

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);

            customFilter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(eq(request), eq(response));
            verify(response).sendRedirect("/contexa/zero-trust/blocked");
        }
    }

    @Test
    void aRequestStoppedByTheBlockInForceIsKeptInItsSession() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/api/customers/CUS-0012");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(false);

            filter.doFilter(request, response, filterChain);

            verify(unanalysed).recordRequest(authentication, ZeroTrustAction.BLOCK);
            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    @Test
    void aRequestStoppedByTheEscalationInForceIsKeptInItsSession() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/api/customers/CUS-0012");
        when(request.getHeader("Accept")).thenReturn("text/html");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.ESCALATE);
            when(actionRedisRepository.getActionFromHash("testUser")).thenReturn(ZeroTrustAction.ESCALATE);

            filter.doFilter(request, response, filterChain);

            verify(unanalysed).recordRequest(authentication, ZeroTrustAction.ESCALATE);
            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    @Test
    void aRequestStoppedOnceTheBlockStepUpIsExhaustedIsKeptInItsSession() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/api/customers/CUS-0012");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);
            when(actionRedisRepository.getBlockMfaFailCount("testUser")).thenReturn(2L);

            filter.doFilter(request, response, filterChain);

            verify(unanalysed, times(1)).recordRequest(authentication, ZeroTrustAction.BLOCK);
            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    @Test
    void aRequestStoppedWhileTheBlockStepUpOpensIsKeptInItsSession() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(request.getRequestURI()).thenReturn("/api/customers/CUS-0012");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);
            when(actionRedisRepository.getBlockMfaFailCount("testUser")).thenReturn(0L);

            filter.doFilter(request, response, filterChain);

            verify(challengeMfaInitializer).initializeChallengeFlow(any(), any(), any());
            verify(unanalysed, times(1)).recordRequest(authentication, ZeroTrustAction.BLOCK);
            verify(filterChain, never()).doFilter(eq(request), eq(response));
        }
    }

    @Test
    void aStepUpRequestLetThroughUnderABlockIsNotRecorded() throws Exception {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        filter.setUnanalysedRequestRecorder(unanalysed);
        when(authUrlProvider.getAllMfaRelatedUrls()).thenReturn(Set.of("/mfa/select-factor"));
        when(request.getRequestURI()).thenReturn("/mfa/select-factor");
        setUpAuthentication();

        try (MockedStatic<SessionFingerprintUtil> fingerprintMock = mockStatic(SessionFingerprintUtil.class)) {
            fingerprintMock.when(() -> SessionFingerprintUtil.generateContextBindingHash(any(HttpServletRequest.class)))
                    .thenReturn(TEST_CONTEXT_BINDING_HASH);
            when(actionRedisRepository.getCurrentAction("testUser", TEST_CONTEXT_BINDING_HASH))
                    .thenReturn(ZeroTrustAction.BLOCK);
            when(actionRedisRepository.isBlockMfaPending("testUser")).thenReturn(true);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(unanalysed, never()).recordRequest(any(), any());
        }
    }

    private void setUpAuthentication() {
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }
}
