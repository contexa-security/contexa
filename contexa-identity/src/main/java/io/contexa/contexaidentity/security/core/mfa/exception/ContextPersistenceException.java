package io.contexa.contexaidentity.security.core.mfa.exception;

public class ContextPersistenceException extends RuntimeException {

    public ContextPersistenceException(String message) {
        super(message);
    }

    public ContextPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}