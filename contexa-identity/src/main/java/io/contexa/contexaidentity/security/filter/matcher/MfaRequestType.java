package io.contexa.contexaidentity.security.filter.matcher;

public enum MfaRequestType {

    FACTOR_SELECTION("Factor selection processing"),

    CHALLENGE_INITIATION("Challenge initiation"),

    OTT_CODE_REQUEST("OTT code request"),

    OTT_CODE_VERIFY("OTT code verification"),

    FACTOR_VERIFICATION("Factor verification"),

    CANCEL_MFA("MFA cancellation"),

    LOGIN_PROCESSING("Login processing"),

    UNKNOWN("Unknown request");

    private final String description;

    MfaRequestType(String description) {
        this.description = description;
    }
    public String getDescription() {
        return description;
    }
}