package io.contexa.contexacommon.enums;

import lombok.Getter;

/**
 * Audit event categories based on 5W1H principle.
 * Each category defines what kind of security event was recorded.
 */
@Getter
public enum AuditEventCategory {

    // Authentication
    AUTHENTICATION_SUCCESS("Authentication succeeded"),
    AUTHENTICATION_FAILURE("Authentication failed"),

    // Authorization
    AUTHORIZATION_GRANTED("Authorization granted"),
    AUTHORIZATION_DENIED("Authorization denied"),

    // Zero Trust AI
    SECURITY_DECISION("AI security decision"),
    SECURITY_ERROR("Security processing error"),
    ADMIN_OVERRIDE("Admin override action"),
    HTTP_ACCESS_BLOCKED("HTTP request blocked by zero trust filter"),

    // User blocking
    USER_BLOCKED("User blocked by AI decision"),
    USER_UNBLOCKED("User unblocked by admin"),
    UNBLOCK_REQUESTED("User requested unblock"),
    SOAR_AUTO_RESPONSE("SOAR automated response executed"),

    // MFA
    MFA_CHALLENGE_ISSUED("MFA challenge issued"),
    MFA_VERIFICATION_SUCCESS("MFA verification succeeded"),
    MFA_VERIFICATION_FAILED("MFA verification failed"),

    // Policy management
    POLICY_CREATED("Policy created"),
    POLICY_UPDATED("Policy updated"),
    POLICY_DELETED("Policy deleted"),
    POLICY_CHANGE("Policy configuration change"),

    // Role management
    ROLE_CREATED("Role created"),
    ROLE_UPDATED("Role updated"),
    ROLE_DELETED("Role deleted"),

    // User management
    USER_CREATED("User account created"),
    USER_MODIFIED("User information modified"),
    USER_DELETED("User account deleted"),

    // Session
    SESSION_CREATED("Session created"),
    SESSION_DESTROYED("Session destroyed"),
    TOKEN_ISSUED("Token issued"),
    TOKEN_REVOKED("Token revoked");

    private final String description;

    AuditEventCategory(String description) {
        this.description = description;
    }
}
