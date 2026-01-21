package io.contexa.contexaidentity.security.exception;

public class TokenCreationException extends RuntimeException {

    public TokenCreationException(String message) {
        super(message);
    }

    public TokenCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}

