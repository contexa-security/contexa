package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaContextValidatorTest {

    @Mock
    private FactorContext factorContext;

    @Test
    void validateMfaContext_shouldReturnError_whenContextIsNull() {
        ValidationResult result = MfaContextValidator.validateMfaContext(null);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.contains("null"));
    }

    @Test
    void validateMfaContext_shouldReturnError_whenSessionIdEmpty() {
        when(factorContext.getMfaSessionId()).thenReturn("");

        ValidationResult result = MfaContextValidator.validateMfaContext(factorContext);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.contains("session ID"));
    }

    @Test
    void validateMfaContext_shouldReturnError_whenTerminalState() {
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(factorContext.getCurrentState()).thenReturn(MfaState.MFA_SUCCESSFUL);

        ValidationResult result = MfaContextValidator.validateMfaContext(factorContext);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.contains("terminal state"));
    }

    @Test
    void validateMfaContext_shouldReturnError_whenUsernameEmpty() {
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(factorContext.getUsername()).thenReturn("");

        ValidationResult result = MfaContextValidator.validateMfaContext(factorContext);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.contains("Username"));
    }

    @Test
    void validateMfaContext_shouldPass_whenValid() {
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(factorContext.getUsername()).thenReturn("testUser");

        ValidationResult result = MfaContextValidator.validateMfaContext(factorContext);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void validateFactorProcessingContext_shouldReturnError_whenNoCurrentFactor() {
        setUpValidBaseContext();
        when(factorContext.getCurrentState()).thenReturn(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(null);
        when(factorContext.getCurrentStepId()).thenReturn("step-1");

        ValidationResult result = MfaContextValidator.validateFactorProcessingContext(factorContext);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.contains("No factor"));
    }

    @Test
    void validateFactorProcessingContext_shouldReturnError_whenInvalidState() {
        setUpValidBaseContext();
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(factorContext.getCurrentStepId()).thenReturn("step-1");

        ValidationResult result = MfaContextValidator.validateFactorProcessingContext(factorContext);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.contains("Invalid state for factor processing"));
    }

    @Test
    void validateFactorSelectionContext_shouldAddWarning_whenNoAvailableFactors() {
        setUpValidBaseContext();
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(factorContext.getAvailableFactors()).thenReturn(null);

        ValidationResult result = MfaContextValidator.validateFactorSelectionContext(factorContext);

        assertThat(result.hasErrors()).isFalse();
        assertThat(result.hasWarnings()).isTrue();
        assertThat(result.getWarnings()).anyMatch(w -> w.contains("No available MFA factors"));
    }

    @Test
    void validateFactorSelectionContext_shouldPass_whenValid() {
        setUpValidBaseContext();
        when(factorContext.getCurrentState()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        when(factorContext.getAvailableFactors()).thenReturn(Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY));

        ValidationResult result = MfaContextValidator.validateFactorSelectionContext(factorContext);

        assertThat(result.hasErrors()).isFalse();
        assertThat(result.hasWarnings()).isFalse();
    }

    private void setUpValidBaseContext() {
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(factorContext.getUsername()).thenReturn("testUser");
    }
}
