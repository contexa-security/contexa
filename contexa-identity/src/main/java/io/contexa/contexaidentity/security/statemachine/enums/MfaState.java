package io.contexa.contexaidentity.security.statemachine.enums;

import lombok.Getter;

@Getter
public enum MfaState {

    NONE("No MFA session"),

    PRIMARY_AUTHENTICATION_COMPLETED("Primary authentication completed"),

    MFA_NOT_REQUIRED("MFA not required"),

    AWAITING_FACTOR_SELECTION("Awaiting secondary factor selection"),
    AWAITING_FACTOR_CHALLENGE_INITIATION("Awaiting secondary factor challenge initiation"),
    FACTOR_CHALLENGE_INITIATED("Challenge sent/generated"),
    FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION("Awaiting user input"),
    FACTOR_VERIFICATION_PENDING("Factor verification in progress"),
    FACTOR_VERIFICATION_IN_PROGRESS("Factor verification processing"),
    FACTOR_VERIFICATION_COMPLETED("Factor verification completed"),

    ALL_FACTORS_COMPLETED("All required factors completed"),
    MFA_SUCCESSFUL("MFA final success"),
    MFA_FAILED_TERMINAL("MFA final failure"),
    MFA_CANCELLED("User cancelled"),
    MFA_SESSION_EXPIRED("Session expired"),
    MFA_SESSION_INVALIDATED("Session invalidated"),
    MFA_RETRY_LIMIT_EXCEEDED("Retry limit exceeded"),
    MFA_SYSTEM_ERROR("System error");

    private final String description;

    MfaState(String description) {
        this.description = description;
    }

    public boolean isTerminal() {
        return this == MFA_SUCCESSFUL ||
                this == MFA_NOT_REQUIRED ||
                this == MFA_FAILED_TERMINAL ||
                this == MFA_CANCELLED ||
                this == MFA_SESSION_EXPIRED ||
                this == MFA_SESSION_INVALIDATED ||
                this == MFA_RETRY_LIMIT_EXCEEDED ||
                this == MFA_SYSTEM_ERROR;
    }

    public boolean isProcessing() {
        return this == AWAITING_FACTOR_CHALLENGE_INITIATION ||
                this == FACTOR_CHALLENGE_INITIATED ||
                this == FACTOR_VERIFICATION_PENDING;
    }
}