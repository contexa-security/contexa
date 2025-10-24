package io.contexa.contexaidentity.security.exception;

/**
 * DSL(Domain Specific Language) 정의의 유효성 검사 과정에서
 * 오류가 발견되었을 때 던져지는 예외입니다.
 * 예를 들어, 설정 충돌, 필수 값 누락 등이 해당됩니다.
 */
public class DslValidationException extends RuntimeException {

    public DslValidationException(String message) {
        super(message);
    }

    public DslValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}

