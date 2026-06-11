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

import java.util.Locale;

public class DelegatedExecutionPolicyContextAdapter {

    public ExecutionPolicyView adapt(DelegatedExecutionPolicyContext context) {
        if (context == null) {
            return new ExecutionPolicyView(
                    null,
                    null,
                    ExecutionSubjectTypes.UNKNOWN,
                    false,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    java.util.List.of(),
                    java.util.List.of(),
                    java.util.List.of(),
                    false,
                    false,
                    java.util.List.of(),
                    java.util.List.of(),
                    null,
                    null,
                    ExecutionProtocolTypes.UNKNOWN,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null);
        }
        String subjectType = context.serviceClientPrincipal()
                ? ExecutionSubjectTypes.SERVICE_CLIENT
                : (context.delegatedExecution() ? ExecutionSubjectTypes.AGENT_RUNTIME : ExecutionSubjectTypes.HUMAN_USER);
        String summary = String.format(Locale.ROOT,
                "%s execution for objective %s under protocol compatibility mode.",
                context.executionMode() != null ? context.executionMode() : "UNKNOWN",
                context.objectiveFamily() != null ? context.objectiveFamily() : "UNSPECIFIED_OBJECTIVE");
        return new ExecutionPolicyView(
                context.tenantId(),
                context.clientId(),
                subjectType,
                context.serviceClientPrincipal(),
                context.executionMode(),
                context.lineageSummary() != null ? context.lineageSummary().lineageState() : null,
                context.actorUserId(),
                context.agentId(),
                context.delegationId(),
                context.taskIntent(),
                context.taskPurpose(),
                context.objectiveId(),
                context.objectiveFamily(),
                context.allowedResourceFamilies(),
                context.allowedOperations(),
                context.allowedToolChain(),
                context.containmentOnly(),
                context.privilegedExportAllowed(),
                context.approvedScopes(),
                context.toolChain(),
                context.permitId(),
                context.approvalId(),
                ExecutionProtocolTypes.UNKNOWN,
                null,
                context.delegationId(),
                null,
                null,
                context.startedAt(),
                context.expiresAt(),
                summary);
    }
}
