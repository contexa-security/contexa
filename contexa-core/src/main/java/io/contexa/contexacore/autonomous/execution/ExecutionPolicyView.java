package io.contexa.contexacore.autonomous.execution;

import java.time.LocalDateTime;
import java.util.List;

public record ExecutionPolicyView(
        String tenantId,
        String clientId,
        String subjectType,
        boolean serviceClientPrincipal,
        String executionMode,
        String lineageState,
        String actorUserId,
        String agentId,
        String delegationId,
        String taskIntent,
        String taskPurpose,
        String objectiveId,
        String objectiveFamily,
        List<String> allowedResourceFamilies,
        List<String> allowedOperations,
        List<String> allowedToolChain,
        boolean containmentOnly,
        boolean privilegedExportAllowed,
        List<String> approvedScopes,
        List<String> toolChain,
        String permitId,
        String approvalId,
        String protocolType,
        String protocolVersion,
        String chainId,
        Integer chainDepth,
        String attestationState,
        LocalDateTime startedAt,
        LocalDateTime expiresAt,
        String summary) {

    public ExecutionPolicyView {
        allowedResourceFamilies = allowedResourceFamilies == null ? List.of() : List.copyOf(allowedResourceFamilies);
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(allowedOperations);
        allowedToolChain = allowedToolChain == null ? List.of() : List.copyOf(allowedToolChain);
        approvedScopes = approvedScopes == null ? List.of() : List.copyOf(approvedScopes);
        toolChain = toolChain == null ? List.of() : List.copyOf(toolChain);
    }

    public boolean delegatedExecution() {
        return DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT.equals(executionMode);
    }

    public boolean objectiveBound() {
        return objectiveFamily != null && !objectiveFamily.isBlank();
    }

    public boolean scopeBound() {
        return !approvedScopes.isEmpty();
    }

    public boolean permitBound() {
        return permitId != null && !permitId.isBlank();
    }

    public boolean approvalBound() {
        return approvalId != null && !approvalId.isBlank();
    }

    public boolean timeBound() {
        return startedAt != null || expiresAt != null;
    }
}