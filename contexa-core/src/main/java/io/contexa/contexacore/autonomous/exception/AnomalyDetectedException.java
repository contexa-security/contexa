package io.contexa.contexacore.autonomous.exception;

import org.springframework.security.access.AccessDeniedException;

public class AnomalyDetectedException extends AccessDeniedException {

    public AnomalyDetectedException(String message) {
        super(message);
    }

    public AnomalyDetectedException(String message, Throwable cause) {
        super(message, cause);
    }
}