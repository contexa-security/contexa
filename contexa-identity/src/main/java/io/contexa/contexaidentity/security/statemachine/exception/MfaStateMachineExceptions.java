package io.contexa.contexaidentity.security.statemachine.exception;

public class MfaStateMachineExceptions {

    public static class InvalidFactorException extends RuntimeException {
        public InvalidFactorException(String message) {
            super(message);
        }
    }

    public static class StateMachineActionException extends RuntimeException {
        public StateMachineActionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class ChallengeGenerationException extends RuntimeException {
        public ChallengeGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class FactorVerificationException extends RuntimeException {
        public FactorVerificationException(String message) {
            super(message);
        }
    }

    public static class StateTransitionException extends RuntimeException {
        public StateTransitionException(String message) {
            super(message);
        }
    }

    public static class SessionExpiredException extends RuntimeException {
        public SessionExpiredException(String message) {
            super(message);
        }
    }

    public static class ConcurrencyException extends RuntimeException {
        public ConcurrencyException(String message) {
            super(message);
        }
    }
}