package io.contexa.contexaidentity.security.utils;

import io.contexa.contexaidentity.security.statemachine.enums.MfaState;

public class AuthUtil {

    /**
     * MfaState가 최종 완료 또는 실패 상태인지 확인합니다.
     * @param state 확인할 MfaState
     * @return 터미널 상태이면 true
     */
    public static boolean isTerminalState(MfaState state) {
        if (state == null) {
            return false;
        }
        return state.isTerminal(); // MfaState enum 자체의 isTerminal() 메소드 활용
    }

    // 필요하다면 다른 유틸리티 메소드 추가
}
