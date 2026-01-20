package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.ChallengeGenerationException;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.FactorVerificationException;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.InvalidFactorException;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.StateTransitionException;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.action.Action;

@Slf4j
@RequiredArgsConstructor
public abstract class AbstractMfaStateAction implements Action<MfaState, MfaEvent>, ApplicationContextAware {

    protected ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public final void execute(StateContext<MfaState, MfaEvent> context) {
        String sessionId = extractSessionId(context);
        log.debug("Executing action {} for session: {}", this.getClass().getSimpleName(), sessionId);

        FactorContext factorContext = null;
        try {
            
            factorContext = extractFactorContext(context);
            if (factorContext == null) {
                throw new IllegalStateException("FactorContext not found in state machine context");
            }

            
            validatePreconditions(context, factorContext);

            
            doExecute(context, factorContext);

            
            updateStateMachineVariables(context, factorContext);

            log.debug("Action {} completed successfully for session: {}",
                    this.getClass().getSimpleName(), sessionId);

        } catch (InvalidFactorException | ChallengeGenerationException |
                 FactorVerificationException | StateTransitionException e) {
            log.error("Business exception in action {} for session: {}: {}",
                    this.getClass().getSimpleName(), sessionId, e.getMessage());

            
            assert factorContext != null;
            factorContext.setLastError(e.getMessage());

            
            handleBusinessException(context, factorContext, e);

            
            throw new MfaStateMachineExceptions.StateMachineActionException(
                    "MFA action failed: " + e.getMessage(), e);

        } catch (Exception e) {
            
            log.error("Unexpected exception in action", e);

            if (factorContext != null) {
                
                handleUnexpectedError(context, factorContext, e);
            }

            
            throw new MfaStateMachineExceptions.StateMachineActionException(
                    "Unexpected error in MFA action", e);
        }
    }

    
    protected void validatePreconditions(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext) throws Exception {
        
        
    }

    
    protected abstract void doExecute(StateContext<MfaState, MfaEvent> context,
                                      FactorContext factorContext) throws Exception;

    
    protected void handleBusinessException(StateContext<MfaState, MfaEvent> context,
                                           FactorContext factorContext,
                                           RuntimeException e) {
        
        if (factorContext != null) {
            factorContext.setLastError(e.getMessage());

            
            if (e instanceof InvalidFactorException) {
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                         MfaEvent.SYSTEM_ERROR);

            } else if (e instanceof ChallengeGenerationException) {
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                         MfaEvent.CHALLENGE_INITIATION_FAILED);

            } else if (e instanceof FactorVerificationException) {
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                         MfaEvent.FACTOR_VERIFICATION_FAILED);
            }
        }
    }

    
    protected void transitionToExpiredState(StateContext<MfaState, MfaEvent> context,
                                            FactorContext factorContext) {
        if (factorContext != null) {
            
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                     MfaEvent.SESSION_TIMEOUT);
            factorContext.setLastError("Session timeout");
        }
    }

    
    protected void handleUnexpectedError(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext,
                                         Exception e) {
        if (factorContext != null) {
            factorContext.setLastError("Unexpected error: " + e.getMessage());
            
            
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                     MfaEvent.SYSTEM_ERROR);
        }

        
        
    }

    
    protected String extractSessionId(StateContext<MfaState, MfaEvent> context) {
        String sessionId = StateContextHelper.getFactorContext(context).getMfaSessionId();
        if (sessionId == null) {
            sessionId = (String) context.getMessageHeader("mfaSessionId");
        }
        if (sessionId == null) {
            sessionId = (String) context.getExtendedState().getVariables().get("sessionId");
        }
        return sessionId;
    }

    
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return StateContextHelper.getFactorContext(context);
    }

    
    protected void updateStateMachineVariables(StateContext<MfaState, MfaEvent> context,
                                               FactorContext factorContext) {
        StateContextHelper.setFactorContext(context, factorContext);
    }

    
    protected AuthenticationFlowConfig findMfaFlowConfig(FactorContext ctx) {
        try {
            if (applicationContext == null) {
                log.error("ApplicationContext is not set for action: {}", this.getClass().getSimpleName());
                return null;
            }

            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            return platformConfig.getFlows().stream()
                .filter(f -> AuthType.MFA.name().equalsIgnoreCase(f.getTypeName()))
                .findFirst()
                .orElse(null);
        } catch (Exception e) {
            log.error("Error loading MFA flow config for session: {}",
                     ctx != null ? ctx.getMfaSessionId() : "unknown", e);
            return null;
        }
    }
}