package io.contexa.contexaiam.asep;

public enum ErrorCode {

    AUTH_FAILED("E001", "인증에 실패했습니다"),
    TOKEN_EXPIRED("E002", "토큰이 만료되었습니다"),
    TOKEN_INVALID("E003", "토큰이 유효하지 않습니다"),
    TOKEN_STORAGE_ERROR("E004", "토큰 저장 중 오류가 발생했습니다"),
    ACCESS_DENIED("E005", "접근이 거부되었습니다");

    private final String code;
    private final String message;

    ErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String code() {
        return code;
    }

    public String message() {
        return message;
    }
}

