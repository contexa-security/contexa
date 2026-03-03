package io.contexa.contexacoreenterprise.soar.approval;

public interface ApprovalResultNotifier {

    void publishResult(String approvalId, boolean approved);
}
