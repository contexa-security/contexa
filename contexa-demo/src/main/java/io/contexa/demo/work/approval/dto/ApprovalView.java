package io.contexa.demo.work.approval.dto;

import java.time.Instant;

public record ApprovalView(
        ApprovalRequestRecord request,
        ApprovalDecisionRecord decision,
        String effectiveStatus,
        Instant observedAt,
        boolean canReview) {
}
