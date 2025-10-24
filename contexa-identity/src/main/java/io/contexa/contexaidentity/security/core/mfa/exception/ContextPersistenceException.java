package io.contexa.contexaidentity.security.core.mfa.exception;

/**
 * ContextPersistence 예외 클래스
 */
public class ContextPersistenceException extends RuntimeException {

    public ContextPersistenceException(String message) {
        super(message);
    }

    public ContextPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}