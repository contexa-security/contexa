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
