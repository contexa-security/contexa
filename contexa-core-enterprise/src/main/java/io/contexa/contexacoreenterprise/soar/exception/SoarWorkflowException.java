package io.contexa.contexacoreenterprise.soar.exception;

public class SoarWorkflowException extends RuntimeException {
    public SoarWorkflowException(String message) {
        super(message);
    }

    public SoarWorkflowException(String message, Throwable cause) {
        super(message, cause);
    }
}