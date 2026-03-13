package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.SessionIdGenerationException;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaFormAuthenticationFilterTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private AuthContextProperties properties;

    @Mock
    private RequestMatcher requestMatcher;

    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @Mock
    private MfaSessionRepository sessionRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private PlatformAuthenticationSuccessHandler successHandler;

    @Mock
    private PlatformAuthenticationFailureHandler failureHandler;

    @Mock
    private SecurityContextHolderStrategy securityContextHolderStrategy;

    @Mock
    private SecurityContextRepository securityContextRepository;

    private MfaFormAuthenticationFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        when(applicationContext.getBean(MfaStateMachineIntegrator.class)).thenReturn(stateMachineIntegrator);
        when(applicationContext.getBean(MfaSessionRepository.class)).thenReturn(sessionRepository);

        io.contexa.contexacommon.properties.MfaSettings mfaSettings = mock(io.contexa.contexacommon.properties.MfaSettings.class);
        when(mfaSettings.getMinimumDelayMs()).thenReturn(0L);
        when(properties.getMfa()).thenReturn(mfaSettings);

        filter = new MfaFormAuthenticationFilter(authenticationManager, applicationContext, properties, requestMatcher);

        // Inject mocked handlers and strategies via reflection
        setField(filter, "successHandler", successHandler);
        setField(filter, "failureHandler", failureHandler);
        setField(filter, "securityContextHolderStrategy", securityContextHolderStrategy);
        setField(filter, "securityContextRepository", securityContextRepository);

        when(securityContextHolderStrategy.createEmptyContext()).thenReturn(new SecurityContextImpl());
    }

    @Nested
    @DisplayName("Constructor validation tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with null authenticationManager should throw")
        void nullAuthManagerThrows() {
            assertThatThrownBy(() -> new MfaFormAuthenticationFilter(
                    null, applicationContext, properties, requestMatcher))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("authenticationManager cannot be null");
        }

        @Test
        @DisplayName("Constructor with null properties should throw")
        void nullPropertiesThrows() {
            assertThatThrownBy(() -> new MfaFormAuthenticationFilter(
                    authenticationManager, applicationContext, null, requestMatcher))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("properties cannot be null");
        }
    }

    @Nested
    @DisplayName("Session ID generation tests")
    class SessionIdGenerationTests {

        @Test
        @DisplayName("Non-distributed repository should generate local session ID")
        void nonDistributedGeneratesLocalId() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            // Verify state machine was initialized with a non-null session ID
            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            FactorContext capturedContext = contextCaptor.getValue();
            assertThat(capturedContext.getMfaSessionId()).isNotNull().isNotEmpty();
        }

        @Test
        @DisplayName("Distributed repository should use distributed session ID generation")
        void distributedUsesDistributedGeneration() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(true);
            when(sessionRepository.generateUniqueSessionId(anyString(), any(HttpServletRequest.class)))
                    .thenReturn("distributed-session-id");

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            assertThat(contextCaptor.getValue().getMfaSessionId()).isEqualTo("distributed-session-id");
        }

        @Test
        @DisplayName("Session ID generation should retry with exponential backoff on failure")
        void sessionIdGenerationRetriesOnFailure() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(true);

            // Fail first 4 times, succeed on 5th via collision resolution
            when(sessionRepository.generateUniqueSessionId(anyString(), any(HttpServletRequest.class)))
                    .thenThrow(new SessionIdGenerationException("collision on attempt 1"))
                    .thenThrow(new SessionIdGenerationException("collision on attempt 2"))
                    .thenThrow(new SessionIdGenerationException("collision on attempt 3"))
                    .thenThrow(new SessionIdGenerationException("collision on attempt 4"))
                    .thenThrow(new SessionIdGenerationException("collision on attempt 5"));

            // On final failure, resolveSessionIdCollision is called
            when(sessionRepository.resolveSessionIdCollision(anyString(), any(HttpServletRequest.class), eq(3)))
                    .thenReturn("resolved-session-id");

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            // Should have attempted 5 times
            verify(sessionRepository, times(5))
                    .generateUniqueSessionId(anyString(), any(HttpServletRequest.class));
            // Then should have called resolveSessionIdCollision
            verify(sessionRepository).resolveSessionIdCollision(anyString(), any(HttpServletRequest.class), eq(3));
        }

        @Test
        @DisplayName("All retry and resolution failures should fallback to local generation")
        void allRetriesExhaustedFallsBackToLocal() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(true);

            when(sessionRepository.generateUniqueSessionId(anyString(), any(HttpServletRequest.class)))
                    .thenThrow(new SessionIdGenerationException("collision"));

            when(sessionRepository.resolveSessionIdCollision(anyString(), any(HttpServletRequest.class), eq(3)))
                    .thenThrow(new RuntimeException("resolution also failed"));

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            // Should still succeed with a locally generated session ID
            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            assertThat(contextCaptor.getValue().getMfaSessionId()).isNotNull().isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Device ID generation tests")
    class DeviceIdGenerationTests {

        @Test
        @DisplayName("Valid X-Device-Id header should be used as device ID")
        void validDeviceIdHeaderIsUsed() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);
            when(request.getHeader("X-Device-Id")).thenReturn("abcdefghijklmnopqrstuvwxyz");

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            FactorContext capturedContext = contextCaptor.getValue();
            Object deviceId = capturedContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID);
            assertThat(deviceId).isEqualTo("abcdefghijklmnopqrstuvwxyz");
        }

        @Test
        @DisplayName("Invalid X-Device-Id header should trigger new device ID generation")
        void invalidDeviceIdHeaderGeneratesNew() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);
            when(request.getHeader("X-Device-Id")).thenReturn("too-short");

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            FactorContext capturedContext = contextCaptor.getValue();
            Object deviceId = capturedContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID);
            assertThat(deviceId).isNotNull();
            assertThat((String) deviceId).isNotEqualTo("too-short");
        }

        @Test
        @DisplayName("UUID format X-Device-Id header should be accepted")
        void uuidDeviceIdHeaderIsAccepted() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);
            String uuidDeviceId = "550e8400-e29b-41d4-a716-446655440000";
            when(request.getHeader("X-Device-Id")).thenReturn(uuidDeviceId);

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            Object deviceId = contextCaptor.getValue().getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID);
            assertThat(deviceId).isEqualTo(uuidDeviceId);
        }

        @Test
        @DisplayName("Distributed repository should generate distributed device ID when no header")
        void distributedDeviceIdGeneration() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(true);
            when(sessionRepository.generateUniqueSessionId(anyString(), any(HttpServletRequest.class)))
                    .thenReturn("dist-session");
            when(request.getHeader("X-Device-Id")).thenReturn(null);
            when(request.getRemoteAddr()).thenReturn("192.168.1.1");
            when(request.getHeader("User-Agent")).thenReturn("TestAgent");

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            Object deviceId = contextCaptor.getValue().getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID);
            assertThat(deviceId).isNotNull();
            assertThat((String) deviceId).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("State machine initialization tests")
    class StateMachineTests {

        @Test
        @DisplayName("Successful authentication should initialize state machine with NONE state")
        void successfulAuthInitializesStateMachineWithNone() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            FactorContext capturedContext = contextCaptor.getValue();
            assertThat(capturedContext.getCurrentState()).isEqualTo(MfaState.NONE);
            assertThat(capturedContext.getFlowTypeName()).isEqualTo("mfa");
        }

        @Test
        @DisplayName("State machine initialization failure should trigger cleanup and failure handler")
        void stateMachineInitFailureTriggersCleanup() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);

            Authentication auth = createSuccessfulAuthentication();
            doThrow(new RuntimeException("SM init failed"))
                    .when(stateMachineIntegrator).initializeStateMachine(any(), any(), any());

            when(sessionRepository.existsSession(anyString())).thenReturn(true);
            doNothing().when(sessionRepository).removeSession(anyString(), any(), any());

            filter.successfulAuthentication(request, response, filterChain, auth);

            // Verify cleanup was attempted
            verify(sessionRepository).existsSession(anyString());
            verify(sessionRepository).removeSession(anyString(), any(), any());
            // Verify failure handler was called
            verify(failureHandler).onAuthenticationFailure(eq(request), eq(response), any());
        }

        @Test
        @DisplayName("FactorContext should contain security info attributes")
        void factorContextContainsSecurityInfo() throws Exception {
            when(sessionRepository.supportsDistributedSync()).thenReturn(false);
            when(request.getRemoteAddr()).thenReturn("10.0.0.1");
            when(request.getHeader("User-Agent")).thenReturn("TestBrowser/1.0");
            when(request.getHeader("X-Device-Id")).thenReturn(null);

            Authentication auth = createSuccessfulAuthentication();
            when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

            filter.successfulAuthentication(request, response, filterChain, auth);

            ArgumentCaptor<FactorContext> contextCaptor = ArgumentCaptor.forClass(FactorContext.class);
            verify(stateMachineIntegrator).initializeStateMachine(contextCaptor.capture(), eq(request), eq(response));

            FactorContext ctx = contextCaptor.getValue();
            assertThat(ctx.getAttribute(FactorContextAttributes.DeviceAndSession.CLIENT_IP))
                    .isEqualTo("10.0.0.1");
            assertThat(ctx.getAttribute(FactorContextAttributes.DeviceAndSession.USER_AGENT))
                    .isEqualTo("TestBrowser/1.0");
            assertThat(ctx.getAttribute(FactorContextAttributes.Timestamps.LOGIN_TIMESTAMP))
                    .isNotNull();
        }
    }

    @Nested
    @DisplayName("Parameter setter tests")
    class ParameterSetterTests {

        @Test
        @DisplayName("setUsernameParameter with empty value should throw")
        void emptyUsernameParameterThrows() {
            assertThatThrownBy(() -> filter.setUsernameParameter(""))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("setPasswordParameter with empty value should throw")
        void emptyPasswordParameterThrows() {
            assertThatThrownBy(() -> filter.setPasswordParameter(""))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("setUsernameParameter with valid value should not throw")
        void validUsernameParameterSetsSuccessfully() {
            assertThatCode(() -> filter.setUsernameParameter("email"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("setPasswordParameter with valid value should not throw")
        void validPasswordParameterSetsSuccessfully() {
            assertThatCode(() -> filter.setPasswordParameter("passcode"))
                    .doesNotThrowAnyException();
        }
    }

    // -- helper methods --

    private Authentication createSuccessfulAuthentication() {
        return UsernamePasswordAuthenticationToken.authenticated("testuser", null, java.util.Collections.emptyList());
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field '" + fieldName + "' not found in class hierarchy");
    }
}
