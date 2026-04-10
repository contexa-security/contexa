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