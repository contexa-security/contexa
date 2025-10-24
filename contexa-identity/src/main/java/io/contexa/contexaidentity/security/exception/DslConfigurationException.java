package io.contexa.contexaidentity.security.exception;

/**
 * DSL 구성 중 발생하는 특정 예외.
 * DSL 정의가 잘못되었거나, 관련 설정을 적용하는 과정에서 문제가 발생했을 때 사용됩니다.
 */
public class DslConfigurationException extends RuntimeException {
    public DslConfigurationException(String message) {
        super(message);
    }

    public DslConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
