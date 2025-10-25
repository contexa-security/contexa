package io.contexa.contexacore.autonomous.exception;

import org.springframework.security.access.AccessDeniedException;

/**
 * 이상 탐지 예외
 *
 * 사용자의 계정에서 비정상적인 활동이 감지되었을 때 발생하는 예외입니다.
 * AccessDeniedException을 상속하여 Spring Security의 예외 처리 체계와 통합됩니다.
 *
 * @author contexa
 * @since 1.0
 */
public class AnomalyDetectedException extends AccessDeniedException {

    public AnomalyDetectedException(String message) {
        super(message);
    }

    public AnomalyDetectedException(String message, Throwable cause) {
        super(message, cause);
    }
}