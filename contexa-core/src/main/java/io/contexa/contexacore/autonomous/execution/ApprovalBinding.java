package io.contexa.contexacore.autonomous.execution;

public record ApprovalBinding(
        String approvalId,
        boolean approvalRequired,
        String approvalCategory) {

    public boolean approvalBound() {
        return approvalId != null && !approvalId.isBlank();
    }
}