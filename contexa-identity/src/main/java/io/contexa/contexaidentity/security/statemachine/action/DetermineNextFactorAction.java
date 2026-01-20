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
        log.debug("Determining next factor for session: {}", sessionId);

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

            log.info("Next factor auto-selected: {} (StepId: {}) for session: {}",
                     decision.getNextFactorType(), decision.getNextStepId(), sessionId);
        } else if (decision.isAllFactorsCompleted()) {
            
            
            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION,
                                       MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED);

            log.info("All required factors completed for session: {}", sessionId);
        } else {
            
            
            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION,
                                       MfaEvent.MFA_REQUIRED_SELECT_FACTOR);

            log.info("Manual factor selection required for session: {}", sessionId);
        }
    }

    
    private void setFactorSpecificAttributes(FactorContext factorContext, AuthType factorType) {
        String sessionId = factorContext.getMfaSessionId();

        switch (factorType) {
            case OTT:
                
                String ottMethod = (String) factorContext.getAttribute(
                    FactorContextAttributes.UserInfo.USER_OTT_PREFERENCE);
                if (ottMethod == null) {
                    ottMethod = "EMAIL";
                }
                factorContext.setAttribute(
                    FactorContextAttributes.FactorInfo.OTT_DELIVERY_METHOD,
                    ottMethod);
                log.debug("OTT delivery method set to: {} for session: {}", ottMethod, sessionId);
                break;

            case PASSKEY:
                
                String userAgent = (String) factorContext.getAttribute(
                    FactorContextAttributes.DeviceAndSession.USER_AGENT);
                String passkeyType = "PLATFORM";
                if (userAgent != null && userAgent.contains("Mobile")) {
                    passkeyType = "MOBILE";
                }
                factorContext.setAttribute(
                    FactorContextAttributes.FactorInfo.PASSKEY_TYPE,
                    passkeyType);
                log.debug("Passkey type set to: {} for session: {}", passkeyType, sessionId);
                break;

            default:
                log.debug("No additional settings for factor: {}", factorType);
        }

        
        factorContext.setAttribute(
            FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT,
            System.currentTimeMillis());
    }
}
