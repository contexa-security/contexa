package io.contexa.contexacommon.enums;

import lombok.Getter;

/**
 * Audit event categories based on 5W1H principle.
 * Each category defines what kind of security event was recorded.
 */
@Getter
public enum AuditEventCategory {

    AUTHENTICATION_SUCCESS("Authentication succeeded"),
    AUTHENTICATION_FAILURE("Authentication failed"),
    AUTHORIZATION_GRANTED("Authorization granted"),
    AUTHORIZATION_DENIED("Authorization denied"),
    ADMIN_OVERRIDE("Admin override action"),
    SECURITY_DECISION("AI security decision"),
    SECURITY_ERROR("Security processing error"),
    USER_BLOCKED("User blocked"),
    USER_UNBLOCKED("User unblocked"),
    POLICY_CHANGE("Policy configuration change"),
    SESSION_CREATED("Session created"),
    SESSION_DESTROYED("Session destroyed"),
    TOKEN_ISSUED("Token issued"),
    TOKEN_REVOKED("Token revoked");

    private final String description;

    AuditEventCategory(String description) {
        this.description = description;
    }
}
