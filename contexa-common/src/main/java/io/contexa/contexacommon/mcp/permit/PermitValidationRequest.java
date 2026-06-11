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
package io.contexa.contexacommon.mcp.permit;

public record PermitValidationRequest(
        String permitId,
        String toolName,
        String requiredScope,
        String executionClass,
        String requestId,
        String approvalId,
        String incidentId,
        String sessionId,
        String argumentsHash,
        String riskLevel,
        String tenantId,
        String userId,
        String zeroTrustAction,
        String contextBindingHashDigest,
        String actorType,
        String executionMode,
        String executionId,
        String delegationId,
        String taskPurpose,
        String approvedScopes,
        String actionApprovalCategory,
        String executionContinuityFingerprint,
        String subjectType,
        String protocolType,
        String protocolVersion,
        String chainId,
        Integer chainDepth,
        String attestationState) {

    public PermitValidationRequest(
            String permitId,
            String toolName,
            String requiredScope,
            String executionClass,
            String requestId,
            String approvalId,
            String incidentId,
            String sessionId,
            String argumentsHash,
            String riskLevel,
            String tenantId,
            String userId,
            String zeroTrustAction,
            String contextBindingHashDigest,
            String actorType,
            String executionMode) {
        this(
                permitId,
                toolName,
                requiredScope,
                executionClass,
                requestId,
                approvalId,
                incidentId,
                sessionId,
                argumentsHash,
                riskLevel,
                tenantId,
                userId,
                zeroTrustAction,
                contextBindingHashDigest,
                actorType,
                executionMode,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    public PermitValidationRequest(
            String permitId,
            String toolName,
            String requiredScope,
            String executionClass,
            String requestId,
            String approvalId,
            String incidentId,
            String sessionId,
            String argumentsHash,
            String riskLevel,
            String tenantId,
            String userId,
            String zeroTrustAction,
            String contextBindingHashDigest,
            String actorType,
            String executionMode,
            String executionId,
            String delegationId,
            String taskPurpose,
            String approvedScopes) {
        this(
                permitId,
                toolName,
                requiredScope,
                executionClass,
                requestId,
                approvalId,
                incidentId,
                sessionId,
                argumentsHash,
                riskLevel,
                tenantId,
                userId,
                zeroTrustAction,
                contextBindingHashDigest,
                actorType,
                executionMode,
                executionId,
                delegationId,
                taskPurpose,
                approvedScopes,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    public PermitValidationRequest(
            String permitId,
            String toolName,
            String requiredScope,
            String executionClass,
            String requestId,
            String approvalId,
            String incidentId,
            String sessionId,
            String argumentsHash,
            String riskLevel,
            String tenantId,
            String userId,
            String zeroTrustAction,
            String contextBindingHashDigest,
            String actorType,
            String executionMode,
            String executionId,
            String delegationId,
            String taskPurpose,
            String approvedScopes,
            String actionApprovalCategory,
            String executionContinuityFingerprint) {
        this(
                permitId,
                toolName,
                requiredScope,
                executionClass,
                requestId,
                approvalId,
                incidentId,
                sessionId,
                argumentsHash,
                riskLevel,
                tenantId,
                userId,
                zeroTrustAction,
                contextBindingHashDigest,
                actorType,
                executionMode,
                executionId,
                delegationId,
                taskPurpose,
                approvedScopes,
                actionApprovalCategory,
                executionContinuityFingerprint,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}
