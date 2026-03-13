package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.filter.handler.MfaRequestHandler;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.filter.handler.StateMachineAwareMfaRequestHandler;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.filter.matcher.MfaUrlMatcher;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaContinuationFilterTest {

    @Mock
    private AuthContextProperties authContextProperties;
    @Mock
    private AuthResponseWriter responseWriter;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private AuthUrlProvider authUrlProvider;
    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;
    @Mock
    private MfaSessionRepository sessionRepository;
    @Mock
    private MfaUrlMatcher urlMatcher;
    @Mock
    private MfaRequestHandler requestHandler;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private FactorContext factorContext;

    private MfaContinuationFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        when(applicationContext.getBean(AuthUrlProvider.class)).thenReturn(authUrlProvider);
        when(applicationContext.getBean(MfaStateMachineIntegrator.class)).thenReturn(stateMachineIntegrator);
        when(applicationContext.getBean(MfaSessionRepository.class)).thenReturn(sessionRepository);

        filter = new MfaContinuationFilter(authContextProperties, responseWriter, applicationContext);

        // Replace internal fields with mocks via reflection for isolated testing
        setField(filter, "urlMatcher", urlMatcher);
        setField(filter, "requestHandler", requestHandler);
    }

    @Test
    void doFilterInternal_shouldReturnServiceUnavailable_whenNotInitialized() throws Exception {
        // initialized is false by default
        filter.doFilterInternal(request, response, filterChain);

        verify(response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                "MFA service is initializing. Please try again in a moment.");
        verifyNoInteractions(filterChain);
    }

    @Test
    void doFilterInternal_shouldPassThrough_whenNotMfaRequest() throws Exception {
        markInitialized();
        when(urlMatcher.isMfaRequest(request)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(stateMachineIntegrator);
    }

    @Test
    void doFilterInternal_shouldSetFactorContextAttribute_whenContextLoaded() throws Exception {
        markInitialized();
        when(urlMatcher.isMfaRequest(request)).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(factorContext);

        // Stub context for valid path
        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState())
                .thenReturn(io.contexa.contexaidentity.security.statemachine.enums.MfaState.AWAITING_FACTOR_SELECTION);
        when(urlMatcher.getRequestType(request)).thenReturn(MfaRequestType.FACTOR_SELECTION);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorSelectionContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(request).setAttribute(MfaContinuationFilter.FACTOR_CONTEXT_ATTR, factorContext);
    }

    @Test
    void doFilterInternal_shouldHandleInvalidContext_whenValidationHasErrors() throws Exception {
        markInitialized();
        when(urlMatcher.isMfaRequest(request)).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(factorContext);
        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(request.getRequestURI()).thenReturn("/mfa/select");
        when(request.getContextPath()).thenReturn("");
        when(authUrlProvider.getPrimaryLoginPage()).thenReturn("/login");
        when(sessionRepository.existsSession("session-1")).thenReturn(true);
        when(sessionRepository.getRepositoryType()).thenReturn("redis");

        // The source sets request.setAttribute(FACTOR_CONTEXT_ATTR, ctx), but since request is a mock,
        // getAttribute won't return the value automatically. Stub it so handleInvalidContext can retrieve ctx.
        when(request.getAttribute(MfaContinuationFilter.FACTOR_CONTEXT_ATTR)).thenReturn(factorContext);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult errorResult = new ValidationResult();
            errorResult.addError("Session is invalid");
            validator.when(() -> MfaContextValidator.validateFactorSelectionContext(factorContext))
                    .thenReturn(errorResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(stateMachineIntegrator).releaseStateMachine("session-1");
        verify(sessionRepository).removeSession("session-1", request, response);
        verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_BAD_REQUEST),
                eq("MFA_SESSION_INVALID"), anyString(), eq("/mfa/select"), anyMap());
    }

    @Test
    void doFilterInternal_shouldDelegateToRequestHandler_whenContextIsTerminal() throws Exception {
        markInitialized();
        when(urlMatcher.isMfaRequest(request)).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(factorContext);
        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState())
                .thenReturn(io.contexa.contexaidentity.security.statemachine.enums.MfaState.MFA_SUCCESSFUL);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorSelectionContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(requestHandler).handleTerminalContext(request, response, factorContext);
    }

    @Test
    void doFilterInternal_shouldDelegateToRequestHandler_whenContextIsValid() throws Exception {
        markInitialized();
        when(urlMatcher.isMfaRequest(request)).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(factorContext);
        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState())
                .thenReturn(io.contexa.contexaidentity.security.statemachine.enums.MfaState.AWAITING_FACTOR_SELECTION);
        when(urlMatcher.getRequestType(request)).thenReturn(MfaRequestType.FACTOR_SELECTION);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorSelectionContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(requestHandler).handleRequest(MfaRequestType.FACTOR_SELECTION, request, response, factorContext, filterChain);
    }

    @Test
    void doFilterInternal_shouldHandleGenericError_whenRequestHandlerThrows() throws Exception {
        markInitialized();
        when(urlMatcher.isMfaRequest(request)).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(factorContext);
        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState())
                .thenReturn(io.contexa.contexaidentity.security.statemachine.enums.MfaState.AWAITING_FACTOR_SELECTION);

        RuntimeException ex = new RuntimeException("unexpected error");
        when(urlMatcher.getRequestType(request)).thenThrow(ex);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorSelectionContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(requestHandler).handleGenericError(request, response, factorContext, ex);
    }

    // -- helper methods --

    private void markInitialized() throws Exception {
        setField(filter, "initialized", true);
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
