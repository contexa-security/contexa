package io.contexa.contexacore.autonomous.exception;

import java.time.LocalDateTime;
import java.util.List;

public record DelegatedExecutionContext(
        String executionId,
        String executionMode,
        String lineageState,
        String actorUserId,
        String agentId,
        String agentRuntimeId,
        String delegationId,
        String parentExecutionId,
        String taskIntent,
        String taskPurpose,
        List<String> requestedScopes,
        List<String> approvedScopes,
        List<String> toolChain,
        String permitId,
        String approvalId,
        LocalDateTime startedAt,
        LocalDateTime expiresAt,
        String objectiveId,
        String objectiveFamily,
        List<String> allowedResourceFamilies,
        List<String> allowedOperations,
        List<String> allowedToolChain,
        boolean containmentOnly,
        boolean privilegedExportAllowed) {

    public static final String EXECUTION_MODE_DIRECT_USER = "DIRECT_USER";
    public static final String EXECUTION_MODE_DELEGATED_AGENT = "DELEGATED_AGENT";
    public static final String LINEAGE_STATE_DIRECT = "DIRECT";
    public static final String LINEAGE_STATE_DECLARED = "DECLARED";
    public static final String LINEAGE_STATE_IMPUTED_SERVICE_CLIENT = "IMPUTED_SERVICE_CLIENT";

    public DelegatedExecutionContext {
        requestedScopes = requestedScopes == null ? List.of() : List.copyOf(requestedScopes);
        approvedScopes = approvedScopes == null ? List.of() : List.copyOf(approvedScopes);
        toolChain = toolChain == null ? List.of() : List.copyOf(toolChain);
        allowedResourceFamilies = allowedResourceFamilies == null ? List.of() : List.copyOf(allowedResourceFamilies);
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(allowedOperations);
        allowedToolChain = allowedToolChain == null ? List.of() : List.copyOf(allowedToolChain);
    }

    public DelegatedExecutionContext(
            String executionId,
            String executionMode,
            String lineageState,
            String actorUserId,
            String agentId,
            String agentRuntimeId,
            String delegationId,
            String parentExecutionId,
            String taskIntent,
            String taskPurpose,
            List<String> requestedScopes,
            List<String> approvedScopes,
            List<String> toolChain,
            String permitId,
            String approvalId,
            LocalDateTime startedAt,
            LocalDateTime expiresAt) {
        this(
                executionId,
                executionMode,
                lineageState,
                actorUserId,
                agentId,
                agentRuntimeId,
                delegationId,
                parentExecutionId,
                taskIntent,
                taskPurpose,
                requestedScopes,
                approvedScopes,
                toolChain,
                permitId,
                approvalId,
                startedAt,
                expiresAt,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                false,
                false);
    }

    public boolean delegatedAgentExecution() {
        return EXECUTION_MODE_DELEGATED_AGENT.equals(executionMode);
    }

    public boolean directUserExecution() {
        return EXECUTION_MODE_DIRECT_USER.equals(executionMode);
    }

    public boolean declaredLineage() {
        return LINEAGE_STATE_DECLARED.equals(lineageState);
    }

    public boolean objectiveBound() {
        return objectiveFamily != null && !objectiveFamily.isBlank() && !allowedOperations.isEmpty();
    }

    public static DelegatedExecutionContext directUser(String actorUserId) {
        return new DelegatedExecutionContext(
                null,
                EXECUTION_MODE_DIRECT_USER,
                LINEAGE_STATE_DIRECT,
                actorUserId,
                null,
                null,
                null,
                null,
                "INTERACTIVE_ACCESS",
                "DIRECT_USER_ACCESS",
                List.of(),
                List.of(),
                List.of(),
                null,
                null,
                null,
                null,
                "DIRECT_USER_ACCESS",
                "DIRECT_USER",
                List.of("INTERACTIVE_RESOURCE"),
                List.of("READ", "WRITE", "EXECUTE"),
                List.of("interactive-user"),
                false,
                true);
    }

    public static DelegatedExecutionContext imputedServiceClient(String actorUserId, String clientId, List<String> approvedScopes) {
        return new DelegatedExecutionContext(
                null,
                EXECUTION_MODE_DELEGATED_AGENT,
                LINEAGE_STATE_IMPUTED_SERVICE_CLIENT,
                actorUserId,
                clientId,
                clientId,
                null,
                null,
                "RUNTIME_SERVICE_CLIENT",
                "UNSPECIFIED_DELEGATED_EXECUTION",
                approvedScopes,
                approvedScopes,
                List.of(),
                null,
                null,
                null,
                null,
                "UNSPECIFIED_DELEGATED_EXECUTION",
                "TENANT_RUNTIME_SERVICE",
                List.of("TENANT_RUNTIME_RESOURCE"),
                List.of("READ", "INGEST", "AUDIT"),
                List.of("runtime-service-client"),
                false,
                false);
    }
}
