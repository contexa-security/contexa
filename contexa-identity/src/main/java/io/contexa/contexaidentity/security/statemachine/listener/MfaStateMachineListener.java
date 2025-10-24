package io.contexa.contexaidentity.security.statemachine.listener;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;

/**
 * MFA State Machine 리스너 인터페이스
 */
public interface MfaStateMachineListener {

    /**
     * 성공적인 상태 전이 시 호출
     */
    void onSuccessfulTransition(String sessionId, MfaState fromState, MfaState toState, MfaEvent event);

    /**
     * 상태 전이 실패 시 호출
     */
    void onFailedTransition(String sessionId, MfaState currentState, MfaEvent event, Exception error);
}