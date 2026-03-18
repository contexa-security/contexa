
package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;

import java.util.Set;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class SelectFactorAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();

        String selectedFactor = (String) context.getMessageHeader("selectedFactor");

        if (selectedFactor == null && factorContext.getCurrentProcessingFactor() != null) {
            selectedFactor = factorContext.getCurrentProcessingFactor().name();
            log.warn("selectedFactor header missing for session: {}, using currentProcessingFactor: {}",
                    sessionId, selectedFactor);
        }

        if (selectedFactor == null) {
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                    MfaEvent.SYSTEM_ERROR);
            throw new IllegalStateException("No factor selected for session: " + sessionId);
        }

        AuthType authType;
        try {
            authType = AuthType.valueOf(selectedFactor.toUpperCase());
        } catch (IllegalArgumentException e) {
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                    MfaEvent.SYSTEM_ERROR);
            throw new IllegalArgumentException("Invalid factor type: " + selectedFactor);
        }

        if (!factorContext.isFactorAvailable(authType)) {
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                    MfaEvent.SYSTEM_ERROR);
            throw new IllegalStateException("Selected factor " + authType +
                    " is not available for user: " + factorContext.getUsername());
        }

        // Prevent selecting the same factor type that is already completed
        boolean alreadyCompleted = factorContext.getCompletedFactors().stream()
                .anyMatch(step -> authType.name().equalsIgnoreCase(step.getType()));
        if (alreadyCompleted) {
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                    MfaEvent.SYSTEM_ERROR);
            throw new IllegalStateException("Factor " + authType +
                    " has already been completed for user: " + factorContext.getUsername());
        }

        factorContext.setCurrentProcessingFactor(authType);

        long selectionTime = System.currentTimeMillis();
        factorContext.setAttribute(FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT, selectionTime);
    }

    @Override
    protected void validatePreconditions(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext) throws Exception {

        if (factorContext.getAvailableFactors() == null ||
                factorContext.getAvailableFactors().isEmpty()) {
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                    MfaEvent.SYSTEM_ERROR);
            throw new IllegalStateException("No MFA factors available for user: " +
                    factorContext.getUsername());
        }

        if (factorContext.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Factor selection attempted in invalid state: {} for session: {}",
                    factorContext.getCurrentState(), factorContext.getMfaSessionId());
        }
    }
}