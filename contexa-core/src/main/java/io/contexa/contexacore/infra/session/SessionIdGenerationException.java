package io.contexa.contexacore.infra.session;


public class SessionIdGenerationException extends RuntimeException {
    public SessionIdGenerationException(String message) {
        super(message);
    }

    public SessionIdGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
