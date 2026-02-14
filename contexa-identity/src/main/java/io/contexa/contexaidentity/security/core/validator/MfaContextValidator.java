package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Set;

@Slf4j
public class MfaContextValidator {

    public static ValidationResult validateMfaContext(FactorContext ctx,
                                                      MfaSessionRepository sessionRepository) {
        ValidationResult result = new ValidationResult();

        if (ctx == null) {
            result.addError("FactorContext is null");
            return result;
        }

        if (!StringUtils.hasText(ctx.getMfaSessionId())) {
            result.addError("MFA session ID is null or empty");
            return result;
        }

        if (ctx.getCurrentState().isTerminal()) {
            result.addError("Context is in terminal state: " + ctx.getCurrentState());
            return result; 
        }

        if (!StringUtils.hasText(ctx.getUsername())) {
            result.addError("Username is null or empty");
        }

        return result;
    }

    public static ValidationResult validateFactorProcessingContext(FactorContext ctx,
                                                                   MfaSessionRepository sessionRepository) {
        ValidationResult result = validateMfaContext(ctx, sessionRepository);

        if (result.hasErrors()) {
            return result; 
        }

        if (ctx.getCurrentProcessingFactor() == null) {
            result.addError("No factor is currently being processed");
        }

        MfaState currentState = ctx.getCurrentState();
        if (!isFactorProcessingState(currentState)) {
            result.addError("Invalid state for factor processing: " + currentState);
        }

        if (!StringUtils.hasText(ctx.getCurrentStepId())) {
            result.addError("Current step ID is null or empty");
        }

        return result;
    }

    public static ValidationResult validateFactorSelectionContext(FactorContext ctx,
                                                                  MfaSessionRepository sessionRepository) {
        ValidationResult result = validateMfaContext(ctx, sessionRepository);

        if (result.hasErrors()) {
            return result;
        }

        MfaState currentState = ctx.getCurrentState();
        if (!isFactorSelectionOrProcessingState(currentState)) {
            result.addError("Invalid state for factor selection: " + currentState);
        }

        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors == null || availableFactors.isEmpty()) {
            result.addWarning("No available MFA factors found");
        }

        return result;
    }

    private static boolean isFactorProcessingState(MfaState state) {
        return state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    private static boolean isFactorSelectionOrProcessingState(MfaState state) {
        return state == MfaState.AWAITING_FACTOR_SELECTION ||
                state == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
    }
}