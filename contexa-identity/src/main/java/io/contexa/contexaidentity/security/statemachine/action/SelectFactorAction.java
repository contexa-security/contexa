
package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
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

        if (!factorContext.getAvailableFactors().contains(authType)) {
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                    MfaEvent.SYSTEM_ERROR);
            throw new IllegalStateException("Selected factor " + authType +
                    " is not available for user: " + factorContext.getUsername());
        }

        factorContext.setCurrentProcessingFactor(authType);

        long selectionTime = System.currentTimeMillis();
        factorContext.setAttribute(FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT, selectionTime);

        switch (authType) {
            case MFA_OTT:

                String ottDeliveryMethod = determineOttDeliveryMethod(context, factorContext);
                factorContext.setAttribute(FactorContextAttributes.FactorInfo.OTT_DELIVERY_METHOD, ottDeliveryMethod);
                break;

            case MFA_PASSKEY:

                String passkeyType = determinePasskeyType(context, factorContext);
                factorContext.setAttribute(FactorContextAttributes.FactorInfo.PASSKEY_TYPE, passkeyType);
                break;

            default:
        }

    }

    private String determineOttDeliveryMethod(StateContext<MfaState, MfaEvent> context,
                                              FactorContext factorContext) {

        String requestedMethod = (String) context.getMessageHeader("ottDeliveryMethod");
        if (requestedMethod != null) {
            return validateOttDeliveryMethod(requestedMethod);
        }

        String userPreference = (String) factorContext.getAttribute(
                FactorContextAttributes.UserInfo.USER_OTT_PREFERENCE);
        if (userPreference != null) {
            return validateOttDeliveryMethod(userPreference);
        }

        String systemDefault = (String) context.getExtendedState().getVariables()
                .getOrDefault("systemOttDeliveryMethod", "SMS");

        return validateOttDeliveryMethod(systemDefault);
    }

    private String determinePasskeyType(StateContext<MfaState, MfaEvent> context,
                                        FactorContext factorContext) {

        String requestedType = (String) context.getMessageHeader("passkeyType");
        if (requestedType != null) {
            return validatePasskeyType(requestedType);
        }

        String userAgent = (String) factorContext.getAttribute(
                FactorContextAttributes.DeviceAndSession.USER_AGENT);
        if (userAgent != null) {
            if (userAgent.contains("Mobile")) {
                return "MOBILE";
            } else if (userAgent.contains("Windows") || userAgent.contains("Mac")) {
                return "PLATFORM";
            }
        }

        return "PLATFORM";
    }

    private String validateOttDeliveryMethod(String method) {
        if (method == null) {
            return "EMAIL";
        }

        String upperMethod = method.toUpperCase();
        return switch (upperMethod) {
            case "SMS", "EMAIL", "VOICE", "PUSH" -> upperMethod;
            default -> {
                log.warn("Invalid OTT delivery method: {}, defaulting to SMS", method);
                yield "EMAIL";
            }
        };
    }

    private String validatePasskeyType(String type) {
        if (type == null) {
            return "PLATFORM";
        }

        String upperType = type.toUpperCase();
        switch (upperType) {
            case "PLATFORM":
            case "CROSS_PLATFORM":
            case "MOBILE":
            case "HYBRID":
                return upperType;
            default:
                log.warn("Invalid passkey type: {}, defaulting to PLATFORM", type);
                return "PLATFORM";
        }
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