package io.contexa.contexaidentity.security.exception;

/**
 * 토큰 검증(validation) 과정에서 문제가 발생했을 때 던지는 예외.
 * 주로 TokenService.refresh()에서 유효하지 않은 리프레시 토큰을 발견했을 때 사용.
 */
public class TokenInvalidException extends RuntimeException {

    public TokenInvalidException(String message) {
        super(message);
    }

    public TokenInvalidException(String message, Throwable cause) {
        super(message, cause);
    }
}

