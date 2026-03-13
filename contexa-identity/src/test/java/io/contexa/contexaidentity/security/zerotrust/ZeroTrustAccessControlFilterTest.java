package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockableResponseWrapper;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
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
                blockingSignalBroadcaster
        );

        when(request.getContextPath()).thenReturn("");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("testUser");
        when(authentication.getAuthorities()).thenReturn(List.of());
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
        when(request.getRequestURI()).thenReturn("/zero-trust/blocked");

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
            verify(response).sendRedirect("/zero-trust/blocked");
        }
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
            verify(response).sendRedirect("/zero-trust/blocked");
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

    private void setUpAuthentication() {
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }
}
