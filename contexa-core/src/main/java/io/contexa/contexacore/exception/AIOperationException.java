package io.contexa.contexacore.exception;

public class AIOperationException extends RuntimeException {
    
    public AIOperationException(String message) {
        super(message);
    }
    
    public AIOperationException(String message, Throwable cause) {
        super(message, cause);
    }
} 