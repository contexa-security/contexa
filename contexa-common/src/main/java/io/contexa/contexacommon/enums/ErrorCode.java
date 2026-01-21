package io.contexa.contexacommon.enums;

public enum ErrorCode {

    AUTH_FAILED("E001", "Authentication failed"),
    TOKEN_EXPIRED("E002", "Token expired"),
    TOKEN_INVALID("E003", "Token invalid"),
    TOKEN_STORAGE_ERROR("E004", "Error occurred while saving token"),
    ACCESS_DENIED("E005", "Access denied");

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
