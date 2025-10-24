package io.contexa.contexacore.exception;

/**
 * IAM 운영 중 발생하는 예외를 처리하는 전용 예외 클래스
 */
public class AIOperationException extends RuntimeException {
    
    public AIOperationException(String message) {
        super(message);
    }
    
    public AIOperationException(String message, Throwable cause) {
        super(message, cause);
    }
} 