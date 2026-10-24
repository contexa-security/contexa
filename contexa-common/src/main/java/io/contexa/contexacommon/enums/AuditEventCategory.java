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
    AGENT_LEARNING_CONTROLLED("Agent learning quarantined, released or removed by an administrator"),
    AGENT_DELEGATION_RECORDED("Delegation to an agent recorded"),
    AGENT_DELEGATION_REVOKED("Delegation to an agent revoked"),
    AGENT_REGISTERED("Agent registered with its OAuth2 client"),
    AGENT_DEREGISTERED("Agent deregistered"),
    AGENT_SPONSOR_CHANGED("Agent sponsor changed"),
    AGENT_SECRET_ROTATED("Agent client secret rotated"),
    AGENT_REMOVED("Agent removed"),
    AGENT_STOPPED("Agent stopped by a security decision or an operator (docs/agent A5-3)"),
    AGENT_RELEASED("Stopped agent released by an administrator (docs/agent A5-3)"),
    AGENT_KILL_SWITCH("Agents of a type or tenant stopped or released at once (docs/agent A5-3)"),
    AGENT_CONFIRMATION_REQUESTED("Agent request waits for the accountable person's confirmation (docs/agent A5-2)"),
    AGENT_CONFIRMATION_APPROVED("Agent request approved by the accountable person (docs/agent A5-2)"),
    AGENT_CONFIRMATION_REJECTED("Agent request refused by the accountable person (docs/agent A5-2)"),
    AGENT_CONFIRMATION_REPORTED("Agent request reported by the accountable person; the agent was stopped (docs/agent A5-2)"),
    AGENT_CONFIRMATION_EXPIRED("Agent confirmation not decided or not used in time (docs/agent A5-2)"),
    AGENT_CONFIRMATION_USED("Approved agent request ran once (docs/agent A5-9)"),
    AGENT_CONFIRMATION_REFUSED("Agent approval offered for another request or not verifiable (docs/agent A5-9)"),
    AGENT_DELEGATION_ENDED("Agent request under a revoked delegation refused (docs/agent F-2)"),
    AGENT_SCOPE_NARROWED("Agent's later requests narrowed by a decision (docs/agent A5-4)"),
    AGENT_CALL_LIMIT_EXCEEDED("Agent passed its call limit and was slowed down or stopped (docs/agent A5-7)"),
    AGENT_DENIAL_RATE_ALARM("Agent's requests refused unusually often (docs/agent A5-7)"),
    RISK_SIGNAL_RECEIVED("Revocation or risk signal received; the subject's decision was invalidated (docs/agent A5-8)"),
    COMPANY_RECORDS_RECORDED("Company records put by an integration or an administrator"),
    COMPANY_RECORDS_DELETED("Company records deleted by an integration or an administrator"),
    SEALED_DECISION_REPLAYED("Sealed decision replayed by an operator with a chosen bundle"),
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
