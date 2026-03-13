package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.Filter;
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

import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaStepFilterWrapperTest {

    @Mock
    private ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    @Mock
    private RequestMatcher mfaFactorProcessingMatcher;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private AuthContextProperties authContextProperties;
    @Mock
    private MfaSettings mfaSettings;
    @Mock
    private AuthResponseWriter responseWriter;
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
    private FactorContext factorContext;

    private MfaStepFilterWrapper filter;

    @BeforeEach
    void setUp() {
        when(authContextProperties.getMfa()).thenReturn(mfaSettings);
        when(mfaSettings.getMinimumDelayMs()).thenReturn(0L);
        when(applicationContext.getBean(MfaStateMachineIntegrator.class)).thenReturn(stateMachineIntegrator);
        when(applicationContext.getBean(MfaSessionRepository.class)).thenReturn(sessionRepository);

        filter = new MfaStepFilterWrapper(
                configuredFactorFilterProvider, mfaFactorProcessingMatcher,
                applicationContext, authContextProperties, responseWriter
        );
    }

    @Test
    void doFilterInternal_shouldPassThrough_whenRequestDoesNotMatch() throws Exception {
        when(mfaFactorProcessingMatcher.matches(request)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(stateMachineIntegrator);
    }

    @Test
    void doFilterInternal_shouldReturnError_whenContextValidationFails() throws Exception {
        when(mfaFactorProcessingMatcher.matches(request)).thenReturn(true);
        when(request.getAttribute("io.contexa.mfa.FactorContext")).thenReturn(null);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);
        when(sessionRepository.getRepositoryType()).thenReturn("memory");
        when(request.getRequestURI()).thenReturn("/mfa/verify");

        // MfaContextValidator.validateFactorProcessingContext(null) returns errors
        filter.doFilterInternal(request, response, filterChain);

        verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_BAD_REQUEST),
                eq("INVALID_MFA_CONTEXT"), anyString(), eq("/mfa/verify"), anyMap());
    }

    @Test
    void doFilterInternal_shouldSendSessionTimeoutEvent_whenSessionExpired() throws Exception {
        when(mfaFactorProcessingMatcher.matches(request)).thenReturn(true);
        when(request.getAttribute("io.contexa.mfa.FactorContext")).thenReturn(factorContext);

        // Stub context so validation passes
        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState()).thenReturn(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        when(factorContext.getFlowTypeName()).thenReturn("standard");
        when(factorContext.getCurrentStepId()).thenReturn("step-1");
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(factorContext.getAttemptCount(AuthType.MFA_OTT)).thenReturn(0);

        // Simulate expired session
        when(factorContext.getAttribute("challengeInitiatedAt")).thenReturn(1L);
        when(mfaSettings.isChallengeExpired(1L)).thenReturn(true);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorProcessingContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(stateMachineIntegrator).sendEvent(MfaEvent.SESSION_TIMEOUT, factorContext, request);
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "MFA session expired");
    }

    @Test
    void doFilterInternal_shouldSendRetryLimitExceededEvent_whenRetryLimitExceeded() throws Exception {
        when(mfaFactorProcessingMatcher.matches(request)).thenReturn(true);
        when(request.getAttribute("io.contexa.mfa.FactorContext")).thenReturn(factorContext);

        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState()).thenReturn(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        when(factorContext.getFlowTypeName()).thenReturn("standard");
        when(factorContext.getCurrentStepId()).thenReturn("step-1");
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(factorContext.getAttemptCount(AuthType.MFA_OTT)).thenReturn(10);

        // No session expiry
        when(factorContext.getAttribute("challengeInitiatedAt")).thenReturn(null);
        // Retry limit exceeded
        when(mfaSettings.isRetryAllowed(10)).thenReturn(false);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorProcessingContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(stateMachineIntegrator).sendEvent(MfaEvent.RETRY_LIMIT_EXCEEDED, factorContext, request);
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Maximum verification attempts exceeded");
    }

    @Test
    void doFilterInternal_shouldDelegateToFactorFilter_whenAllChecksPass() throws Exception {
        when(mfaFactorProcessingMatcher.matches(request)).thenReturn(true);
        when(request.getAttribute("io.contexa.mfa.FactorContext")).thenReturn(factorContext);

        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState()).thenReturn(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        when(factorContext.getFlowTypeName()).thenReturn("standard");
        when(factorContext.getCurrentStepId()).thenReturn("step-1");
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(factorContext.getAttemptCount(AuthType.MFA_OTT)).thenReturn(0);
        when(factorContext.getAttribute("challengeInitiatedAt")).thenReturn(null);
        when(mfaSettings.isRetryAllowed(0)).thenReturn(true);
        when(stateMachineIntegrator.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, factorContext, request))
                .thenReturn(true);

        Filter delegateFilter = mock(Filter.class);
        FactorIdentifier expectedId = FactorIdentifier.of("standard", "step-1");
        when(configuredFactorFilterProvider.getFilter(expectedId)).thenReturn(delegateFilter);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorProcessingContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(delegateFilter).doFilter(request, response, filterChain);
    }

    @Test
    void doFilterInternal_shouldReturnError_whenStateMachineRejectsEvent() throws Exception {
        when(mfaFactorProcessingMatcher.matches(request)).thenReturn(true);
        when(request.getAttribute("io.contexa.mfa.FactorContext")).thenReturn(factorContext);

        when(factorContext.getMfaSessionId()).thenReturn("session-1");
        when(factorContext.getCurrentState()).thenReturn(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        when(factorContext.getFlowTypeName()).thenReturn("standard");
        when(factorContext.getCurrentStepId()).thenReturn("step-1");
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(factorContext.getAttemptCount(AuthType.MFA_OTT)).thenReturn(0);
        when(factorContext.getAttribute("challengeInitiatedAt")).thenReturn(null);
        when(mfaSettings.isRetryAllowed(0)).thenReturn(true);
        when(stateMachineIntegrator.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, factorContext, request))
                .thenReturn(false);

        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            ValidationResult validResult = new ValidationResult();
            validator.when(() -> MfaContextValidator.validateFactorProcessingContext(factorContext))
                    .thenReturn(validResult);

            filter.doFilterInternal(request, response, filterChain);
        }

        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state for factor verification");
    }
}
