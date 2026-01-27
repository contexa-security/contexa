package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.NextFactorDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class DetermineNextFactorAction extends AbstractMfaStateAction {

    private final MfaPolicyProvider policyProvider;

    public DetermineNextFactorAction(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                            FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        
        NextFactorDecision decision = policyProvider.evaluateNextFactor(factorContext);

        if (decision.getErrorMessage() != null) {
            log.error("Error determining next factor: {}", decision.getErrorMessage());
            factorContext.changeState(MfaState.MFA_SYSTEM_ERROR);
            factorContext.setLastError(decision.getErrorMessage());
            return;
        }

        if (decision.isHasNextFactor()) {
            
            factorContext.setCurrentProcessingFactor(decision.getNextFactorType());
            factorContext.setCurrentStepId(decision.getNextStepId());

            setFactorSpecificAttributes(factorContext, decision.getNextFactorType());

            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION, MfaEvent.INITIATE_CHALLENGE_AUTO);

                    } else if (decision.isAllFactorsCompleted()) {

            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION,
                                       MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED);

                    } else {

            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION,
                                       MfaEvent.MFA_REQUIRED_SELECT_FACTOR);

                    }
    }

    private void setFactorSpecificAttributes(FactorContext factorContext, AuthType factorType) {
        String sessionId = factorContext.getMfaSessionId();

        switch (factorType) {
            case MFA_OTT:
                
                String ottMethod = (String) factorContext.getAttribute(
                    FactorContextAttributes.UserInfo.USER_OTT_PREFERENCE);
                if (ottMethod == null) {
                    ottMethod = "EMAIL";
                }
                factorContext.setAttribute(
                    FactorContextAttributes.FactorInfo.OTT_DELIVERY_METHOD,
                    ottMethod);
                                break;

            case MFA_PASSKEY:
                
                String userAgent = (String) factorContext.getAttribute(
                    FactorContextAttributes.DeviceAndSession.USER_AGENT);
                String passkeyType = "PLATFORM";
                if (userAgent != null && userAgent.contains("Mobile")) {
                    passkeyType = "MOBILE";
                }
                factorContext.setAttribute(
                    FactorContextAttributes.FactorInfo.PASSKEY_TYPE,
                    passkeyType);
                                break;

            default:
                        }

        factorContext.setAttribute(
            FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT,
            System.currentTimeMillis());
    }
}
