package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

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
        when(request.getRequestURI()).thenReturn("/zero-trust/blocked");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("현재 action이 CHALLENGE가 아니면 요청을 그대로 통과시킨다")
    void pass() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(actionRepository.getCurrentAction(eq("testUser"), anyString())).thenReturn(ZeroTrustAction.ALLOW);
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
        when(actionRepository.getCurrentAction(eq("testUser"), anyString())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(false);

        filter.doFilter(request, response, filterChain);

        verify(response).sendError(
                eq(HttpServletResponse.SC_SERVICE_UNAVAILABLE),
                eq("MFA service temporarily unavailable")
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
        when(actionRepository.getCurrentAction(eq("testUser"), anyString())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(true);

        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getCurrentState()).thenReturn(
                io.contexa.contexaidentity.security.statemachine.enums.MfaState.AWAITING_FACTOR_SELECTION);
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
        when(actionRepository.getCurrentAction(eq("testUser"), anyString())).thenReturn(ZeroTrustAction.CHALLENGE);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(true);

        when(challengeMfaInitializer.initializeChallengeFlow(any(), any(), any()))
                .thenThrow(new RuntimeException("Test error"));

        filter.doFilter(request, response, filterChain);

        verify(lockService).unlock(anyString(), anyString());
    }

    private void setUpAuthentication() {
        when(authentication.getName()).thenReturn("testUser");
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private void setUpChallengeAuthentication() {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority(
                ZeroTrustAction.CHALLENGE.getGrantedAuthority()
        )));
        setUpAuthentication();
    }
}
