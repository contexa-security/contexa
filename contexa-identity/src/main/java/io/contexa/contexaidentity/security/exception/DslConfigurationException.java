package io.contexa.contexaidentity.security.exception;

public class DslConfigurationException extends RuntimeException {
    public DslConfigurationException(String message) {
        super(message);
    }

    public DslConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
