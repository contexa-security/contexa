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
package io.contexa.contexacore.autonomous.execution;

public record ExecutionEnvelope(
        DelegatedExecutionContext delegatedExecutionContext,
        ObjectiveDescriptor objectiveDescriptor,
        AuthorizationBoundary authorizationBoundary,
        PermitBinding permitBinding,
        ApprovalBinding approvalBinding,
        ExecutionWindow executionWindow,
        AttestationEnvelope attestationEnvelope,
        ExecutionProvenance provenance) {

    public String executionId() {
        return delegatedExecutionContext != null ? delegatedExecutionContext.executionId() : null;
    }

    public String executionMode() {
        return delegatedExecutionContext != null ? delegatedExecutionContext.executionMode() : null;
    }

    public String lineageState() {
        return delegatedExecutionContext != null ? delegatedExecutionContext.lineageState() : null;
    }

    public String delegationId() {
        return delegatedExecutionContext != null ? delegatedExecutionContext.delegationId() : null;
    }

    public String parentExecutionId() {
        return delegatedExecutionContext != null ? delegatedExecutionContext.parentExecutionId() : null;
    }

    public String agentId() {
        return delegatedExecutionContext != null ? delegatedExecutionContext.agentId() : null;
    }
}