package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.domain.LoginRequest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BaseAuthenticationFilterTest {

    @Mock
    private RequestMatcher requestMatcher;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private AuthContextProperties properties;
    @Mock
    private MfaSettings mfaSettings;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;

    private TestableBaseAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        when(properties.getMfa()).thenReturn(mfaSettings);
        when(mfaSettings.getMinimumDelayMs()).thenReturn(0L);
        filter = new TestableBaseAuthenticationFilter(requestMatcher, authenticationManager, properties);
    }

    @Test
    void shouldPassThrough_whenRequestDoesNotMatch() throws Exception {
        when(requestMatcher.matches(request)).thenReturn(false);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void validateLoginRequest_shouldThrowOnEmptyUsername() {
        LoginRequest login = new LoginRequest("", "password123");

        assertThatThrownBy(() -> filter.callValidateLoginRequest(login))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void validateLoginRequest_shouldThrowOnTooLongUsername() {
        String longUsername = "a".repeat(101);
        LoginRequest login = new LoginRequest(longUsername, "password123");

        assertThatThrownBy(() -> filter.callValidateLoginRequest(login))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username too long");
    }

    @Test
    void validateLoginRequest_shouldThrowOnTooLongPassword() {
        String longPassword = "p".repeat(201);
        LoginRequest login = new LoginRequest("validUser", longPassword);

        assertThatThrownBy(() -> filter.callValidateLoginRequest(login))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password too long");
    }

    @Test
    void validateLoginRequest_shouldAcceptValidRequest() {
        LoginRequest login = new LoginRequest("validUser", "validPassword");

        // Should not throw
        filter.callValidateLoginRequest(login);
    }

    @Test
    void getClientIpAddress_shouldExtractFromXForwardedFor() {
        when(request.getHeader("X-Forwarded-For")).thenReturn("192.168.1.100, 10.0.0.1");

        String ip = filter.callGetClientIpAddress(request);

        assertThat(ip).isEqualTo("192.168.1.100");
    }

    @Test
    void getClientIpAddress_shouldFallbackToRemoteAddr() {
        when(request.getRemoteAddr()).thenReturn("172.16.0.50");

        String ip = filter.callGetClientIpAddress(request);

        assertThat(ip).isEqualTo("172.16.0.50");
    }

    /**
     * Concrete subclass to test the abstract BaseAuthenticationFilter.
     */
    private static class TestableBaseAuthenticationFilter extends BaseAuthenticationFilter {

        private boolean successCalled = false;
        private boolean failureCalled = false;

        protected TestableBaseAuthenticationFilter(RequestMatcher requestMatcher,
                                                    AuthenticationManager authenticationManager,
                                                    AuthContextProperties properties) {
            super(requestMatcher, authenticationManager, properties);
        }

        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                 FilterChain chain, Authentication authentication)
                throws IOException, ServletException {
            successCalled = true;
        }

        @Override
        protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                   AuthenticationException failed)
                throws IOException, ServletException {
            failureCalled = true;
        }

        // Expose protected methods for testing
        void callValidateLoginRequest(LoginRequest login) {
            validateLoginRequest(login);
        }

        String callGetClientIpAddress(HttpServletRequest request) {
            return getClientIpAddress(request);
        }
    }
}
