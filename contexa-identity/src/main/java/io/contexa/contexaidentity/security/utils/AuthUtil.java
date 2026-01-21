package io.contexa.contexaidentity.security.utils;

import io.contexa.contexaidentity.security.statemachine.enums.MfaState;

public class AuthUtil {

    public static boolean isTerminalState(MfaState state) {
        if (state == null) {
            return false;
        }
        return state.isTerminal(); 
    }

}
