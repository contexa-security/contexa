package io.contexa.contexacoreenterprise.soar.approval;

public class LocalApprovalResultNotifier implements ApprovalResultNotifier {

    @Override
    public void publishResult(String approvalId, boolean approved) {
        // Standalone: approval result is already delivered via CompletableFuture and Spring Events
    }
}
