package io.contexa.contexacore.autonomous.blocking;

/**
 * Unchecked exception thrown when a blocked user's response must be aborted.
 * Uses RuntimeException so that PrintWriter cannot swallow it
 * (PrintWriter only catches IOException internally).
 */
public class ResponseBlockedException extends RuntimeException {

    public ResponseBlockedException(String message) {
        super(message);
    }
}
