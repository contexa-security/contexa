package io.contexa.contexacore.infra.session;

/**
 * 세션 ID 생성 실패 예외
 */
public class SessionIdGenerationException extends RuntimeException {
    public SessionIdGenerationException(String message) {
        super(message);
    }

    public SessionIdGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
