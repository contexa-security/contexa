package io.contexa.contexacore.autonomous.exception;


import java.time.LocalDateTime;
import java.util.List;

public record DelegatedExecutionPolicyContext(
        String tenantId,
        String clientId,
        boolean serviceClientPrincipal,
        String executionMode,
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
        String capability,
        String operation,
        String resourceFingerprint,
        String requestFingerprint,
        String permitId,
        String approvalId,
        LocalDateTime startedAt,
        LocalDateTime expiresAt,
        DelegatedExecutionLineageSummary lineageSummary) {

    public DelegatedExecutionPolicyContext {
        allowedResourceFamilies = allowedResourceFamilies == null ? List.of() : List.copyOf(allowedResourceFamilies);
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(allowedOperations);
        allowedToolChain = allowedToolChain == null ? List.of() : List.copyOf(allowedToolChain);
        approvedScopes = approvedScopes == null ? List.of() : List.copyOf(approvedScopes);
        toolChain = toolChain == null ? List.of() : List.copyOf(toolChain);
    }

    public static DelegatedExecutionPolicyContext from(DelegatedExecutionGraph graph) {
        if (graph == null) {
            return new DelegatedExecutionPolicyContext(
                    null,
                    null,
                    false,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    false,
                    false,
                    List.of(),
                    List.of(),
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    DelegatedExecutionLineageSummary.from((DelegatedExecutionContext) null));
        }
        DelegatedExecutionContext context = graph.context();
        DelegatedExecutionLineageSummary lineageSummary = DelegatedExecutionLineageSummary.from(graph);
        return new DelegatedExecutionPolicyContext(
                graph.tenantId(),
                graph.clientId(),
                graph.serviceClientPrincipal(),
                context != null ? context.executionMode() : null,
                context != null ? context.actorUserId() : null,
                context != null ? context.agentId() : null,
                context != null ? context.delegationId() : null,
                context != null ? context.taskIntent() : null,
                context != null ? context.taskPurpose() : null,
                context != null ? context.objectiveId() : null,
                context != null ? context.objectiveFamily() : null,
                context != null ? context.allowedResourceFamilies() : List.of(),
                context != null ? context.allowedOperations() : List.of(),
                context != null ? context.allowedToolChain() : List.of(),
                context != null && context.containmentOnly(),
                context != null && context.privilegedExportAllowed(),
                context != null ? context.approvedScopes() : List.of(),
                context != null ? context.toolChain() : List.of(),
                graph.capability(),
                graph.operation(),
                graph.resourceFingerprint(),
                graph.requestFingerprint(),
                context != null ? context.permitId() : null,
                context != null ? context.approvalId() : null,
                context != null ? context.startedAt() : null,
                graph.expiresAt(),
                lineageSummary);
    }

    public boolean delegatedExecution() {
        return lineageSummary != null && lineageSummary.delegatedExecution();
    }

    public boolean directUserExecution() {
        return !delegatedExecution();
    }

    public boolean objectiveBound() {
        return lineageSummary != null && lineageSummary.objectiveBound();
    }

    public boolean scopeBound() {
        return lineageSummary != null && lineageSummary.scopeBound();
    }

    public boolean permitBound() {
        return lineageSummary != null && lineageSummary.permitBound();
    }

    public boolean approvalBound() {
        return lineageSummary != null && lineageSummary.approvalBound();
    }

    public boolean timeBound() {
        return lineageSummary != null && lineageSummary.timeBound();
    }

    public boolean mutatingOperation() {
        return operation != null && !"READ".equalsIgnoreCase(operation) && !"QUERY".equalsIgnoreCase(operation);
    }
}