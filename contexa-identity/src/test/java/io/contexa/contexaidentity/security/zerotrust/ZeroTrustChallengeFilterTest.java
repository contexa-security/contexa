package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
                lockService
        );

        when(request.getContextPath()).thenReturn("");
        when(authUrlProvider.getMfaPageUrls()).thenReturn(Set.of(
                "/mfa/select-factor", "/mfa/failure", "/mfa/success",
                "/mfa/ott/request-code", "/mfa/ott/challenge",
                "/mfa/passkey/challenge", "/mfa/recovery/challenge"
        ));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldNotFilter_mfaPaths() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/mfa/verify");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotFilter_zeroTrustPaths() throws Exception {
        when(request.getRequestURI()).thenReturn("/zero-trust/blocked");

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldPassThrough_whenNoChallengeAuthority() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getAuthorities()).thenReturn(List.of());
        setUpAuthentication();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldPassThrough_whenNotAuthenticated() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        // No authentication in SecurityContext

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldReturnServiceUnavailable_whenLockFails() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpAuthenticationWithChallengeAuthority();
        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(false);

        filter.doFilter(request, response, filterChain);

        verify(response).sendError(
                eq(HttpServletResponse.SC_SERVICE_UNAVAILABLE),
                eq("MFA service temporarily unavailable")
        );
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldInitializeChallengeFlow_whenNoExistingSession() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        when(request.getHeader("Accept")).thenReturn("text/html");
        setUpAuthenticationWithChallengeAuthority();

        when(sessionRepository.getSessionId(request)).thenReturn(null);
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
    @SuppressWarnings("unchecked")
    void shouldUnlockAfterProcessing() throws Exception {
        when(request.getRequestURI()).thenReturn("/dashboard");
        setUpAuthenticationWithChallengeAuthority();

        when(sessionRepository.getSessionId(request)).thenReturn(null);
        when(lockService.tryLock(anyString(), anyString(), any())).thenReturn(true);

        when(challengeMfaInitializer.initializeChallengeFlow(any(), any(), any()))
                .thenThrow(new RuntimeException("Test error"));

        filter.doFilter(request, response, filterChain);

        verify(lockService).unlock(anyString(), anyString());
    }

    private void setUpAuthentication() {
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    @SuppressWarnings("unchecked")
    private void setUpAuthenticationWithChallengeAuthority() {
        String challengeAuthority = ZeroTrustAction.CHALLENGE.getGrantedAuthority();
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("testUser");
        List authorities = List.of(new SimpleGrantedAuthority(challengeAuthority));
        when(authentication.getAuthorities()).thenReturn(authorities);
        setUpAuthentication();
    }
}
