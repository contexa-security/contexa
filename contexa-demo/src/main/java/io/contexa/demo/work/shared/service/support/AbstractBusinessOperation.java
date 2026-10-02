package io.contexa.demo.work.shared.service.support;

import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;

public abstract class AbstractBusinessOperation {

    private final ApprovalUsageQuery approvals;

    protected AbstractBusinessOperation(ApprovalUsageQuery approvals) {
        this.approvals = approvals;
    }

    protected void requireApproval(WorkRequestSnapshot snapshot) {
        approvals.requireUsable(snapshot.approval());
    }
}
