package io.contexa.contexaidentity.security.exception;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;

public class InvalidTransitionException extends RuntimeException {
    private final MfaState state;
    private final MfaEvent event;

    public InvalidTransitionException(MfaState state, MfaEvent event) {
        super(String.format("Cannot transition from %s on event %s", state, event));
        this.state = state;
        this.event = event;
    }

    public MfaState getState() {
        return state;
    }

    public MfaEvent getEvent() {
        return event;
    }
}

