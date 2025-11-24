package io.contexa.contexaiam.aiam.service;

import io.contexa.contexacore.soar.approval.ApprovalService;

public class SoarActionService {

    private final ApprovalService approvalService;

    public SoarActionService(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    public void handleApproval(String approvalId, boolean isApproved, String comment, String reviewer) {
        approvalService.handleApprovalResponse(approvalId, isApproved, comment, reviewer);
    }
}
