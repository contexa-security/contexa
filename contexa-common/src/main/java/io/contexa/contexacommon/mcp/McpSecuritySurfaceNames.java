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
package io.contexa.contexacommon.mcp;

public final class McpSecuritySurfaceNames {

    public static final String ZERO_TRUST_POLICY_RESOURCE = "zero_trust_policy_summary";
    public static final String TOOL_SCOPE_CATALOG_RESOURCE = "tool_scope_catalog";
    public static final String TENANT_POLICY_RESOURCE = "tenant-policy";
    public static final String INCIDENT_CONTEXT_RESOURCE = "incident-context";
    public static final String AUDIT_SUMMARY_RESOURCE = "audit-summary";
    public static final String SECURITY_PLAYBOOK_RESOURCE = "security-playbook";

    public static final String SECURITY_RESPONSE_PLAYBOOK_PROMPT = "security_response_playbook";
    public static final String HIGH_RISK_ACTION_GUARDRAIL_PROMPT = "high_risk_action_guardrail";
    public static final String APPROVED_INCIDENT_PLAYBOOK_PROMPT = "approved-incident-playbook";

    private McpSecuritySurfaceNames() {
    }
}
