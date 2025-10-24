package io.contexa.contexaidentity.security.core.mfa.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.exception.InvalidTransitionException;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;

/**
 * MFA 상태 전이를 처리하는 핸들러 인터페이스.
 * 각 구현체는 특정 MfaState 에서 특정 MfaEvent가 발생했을 때
 * 다음 MfaState를 결정하는 로직을 담당합니다.
 */
public interface MfaStateHandler {

    /**
     * 이 핸들러가 주어진 MfaState를 지원하는지 여부를 반환합니다.
     * 하나의 핸들러가 여러 상태를 지원할 수 있습니다.
     * @param state 검사할 MfaState
     * @return 지원하면 true, 그렇지 않으면 false
     */
    boolean supports(MfaState state);

    /**
     * 주어진 이벤트와 컨텍스트를 기반으로 다음 MfaState를 결정하여 반환합니다.
     * @param event 발생한 MfaEvent
     * @param ctx 현재 FactorContext
     * @return 다음 MfaState
     * @throws InvalidTransitionException 현재 상태에서 지원하지 않는 이벤트가 발생한 경우
     * @throws IllegalStateException 기타 로직 오류
     */
    MfaState handleEvent(MfaEvent event, FactorContext ctx) throws InvalidTransitionException, IllegalStateException;
}

