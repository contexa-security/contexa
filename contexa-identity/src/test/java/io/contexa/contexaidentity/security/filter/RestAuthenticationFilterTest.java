package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RestAuthenticationFilterTest {

    @Mock
    private RequestMatcher requestMatcher;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private AuthContextProperties properties;
    @Mock
    private MfaSettings mfaSettings;
    @Mock
    private TokenService tokenService;
    @Mock
    private AuthResponseWriter responseWriter;
    @Mock
    private PlatformAuthenticationSuccessHandler successHandler;
    @Mock
    private PlatformAuthenticationFailureHandler failureHandler;
    @Mock
    private SecurityContextHolderStrategy securityContextHolderStrategy;
    @Mock
    private SecurityContextRepository securityContextRepository;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private Authentication authentication;

    private RestAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        when(properties.getMfa()).thenReturn(mfaSettings);
        when(mfaSettings.getMinimumDelayMs()).thenReturn(0L);
        when(securityContextHolderStrategy.createEmptyContext()).thenReturn(securityContext);

        filter = new RestAuthenticationFilter(
                requestMatcher, authenticationManager, properties, tokenService, responseWriter
        );
        filter.setSuccessHandler(successHandler);
        filter.setFailureHandler(failureHandler);
        filter.setSecurityContextHolderStrategy(securityContextHolderStrategy);
        filter.setSecurityContextRepository(securityContextRepository);
    }

    @Test
    void successfulAuthentication_shouldSetSecurityContext() throws Exception {
        filter.successfulAuthentication(request, response, filterChain, authentication);

        verify(securityContext).setAuthentication(authentication);
        verify(securityContextHolderStrategy).setContext(securityContext);
    }

    @Test
    void successfulAuthentication_shouldSaveContextToRepository() throws Exception {
        filter.successfulAuthentication(request, response, filterChain, authentication);

        verify(securityContextRepository).saveContext(eq(securityContext), eq(request), eq(response));
    }

    @Test
    void successfulAuthentication_shouldCallSuccessHandler() throws Exception {
        filter.successfulAuthentication(request, response, filterChain, authentication);

        verify(successHandler).onAuthenticationSuccess(request, response, authentication);
    }

    @Test
    void unsuccessfulAuthentication_shouldClearContext() throws Exception {
        BadCredentialsException exception = new BadCredentialsException("bad credentials");

        filter.unsuccessfulAuthentication(request, response, exception);

        verify(securityContextHolderStrategy).clearContext();
    }

    @Test
    void unsuccessfulAuthentication_shouldCallFailureHandler() throws Exception {
        BadCredentialsException exception = new BadCredentialsException("bad credentials");

        filter.unsuccessfulAuthentication(request, response, exception);

        verify(failureHandler).onAuthenticationFailure(request, response, exception);
    }
}
