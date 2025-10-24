package io.contexa.contexaidentity.security.statemachine.support;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.StateMachine;

public class StateContextHelper {

    public static final String FACTOR_CONTEXT_KEY = "factorContext";

    private StateContextHelper() {}

    public static FactorContext getFactorContext(ExtendedState extendedState) {
        if (extendedState == null) return null;
        return extendedState.get(FACTOR_CONTEXT_KEY, FactorContext.class);
    }

    public static void setFactorContext(ExtendedState extendedState, FactorContext factorContext) {
        if (extendedState != null) {
            extendedState.getVariables().put(FACTOR_CONTEXT_KEY, factorContext);
        }
    }

    public static FactorContext getFactorContext(StateMachine<MfaState, MfaEvent> stateMachine) {
        if (stateMachine == null) return null;
        return getFactorContext(stateMachine.getExtendedState());
    }

    public static void setFactorContext(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext factorContext) {
        if (stateMachine != null) {
            setFactorContext(stateMachine.getExtendedState(), factorContext);
        }
    }

    public static FactorContext getFactorContext(StateContext<MfaState, MfaEvent> context) {
        if (context == null) return null;
        return getFactorContext(context.getExtendedState());
    }

    public static void setFactorContext(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        if (context != null) {
            setFactorContext(context.getExtendedState(), factorContext);
        }
    }
}