/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

    SECURITY_DECISION("AI security decision"),
    SECURITY_ERROR("Security processing error"),
    ADMIN_OVERRIDE("Admin override action"),
    HTTP_ACCESS_BLOCKED("HTTP request blocked by zero trust filter"),

    USER_BLOCKED("User blocked by AI decision"),
    USER_UNBLOCKED("User unblocked by admin"),
    UNBLOCK_REQUESTED("User requested unblock"),
    SOAR_AUTO_RESPONSE("SOAR automated response executed"),

    MFA_CHALLENGE_ISSUED("MFA challenge issued"),
    MFA_VERIFICATION_SUCCESS("MFA verification succeeded"),
    MFA_VERIFICATION_FAILED("MFA verification failed"),

    POLICY_CREATED("Policy created"),
    POLICY_UPDATED("Policy updated"),
    POLICY_DELETED("Policy deleted"),
    POLICY_CHANGE("Policy configuration change"),

    ROLE_CREATED("Role created"),
    ROLE_UPDATED("Role updated"),
    ROLE_DELETED("Role deleted"),

    USER_CREATED("User account created"),
    USER_MODIFIED("User information modified"),
    USER_DELETED("User account deleted"),

    SESSION_CREATED("Session created"),
    SESSION_DESTROYED("Session destroyed"),
    TOKEN_ISSUED("Token issued"),
    TOKEN_REVOKED("Token revoked");

    private final String description;

    AuditEventCategory(String description) {
        this.description = description;
    }
}
