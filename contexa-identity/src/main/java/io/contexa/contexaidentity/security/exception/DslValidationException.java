package io.contexa.contexaidentity.security.exception;

public class DslValidationException extends RuntimeException {

    public DslValidationException(String message) {
        super(message);
    }

    public DslValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}

