package io.contexa.contexaidentity.security.statemachine.listener;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;

public interface MfaStateMachineListener {

    void onSuccessfulTransition(String sessionId, MfaState fromState, MfaState toState, MfaEvent event);

    void onFailedTransition(String sessionId, MfaState currentState, MfaEvent event, Exception error);
}