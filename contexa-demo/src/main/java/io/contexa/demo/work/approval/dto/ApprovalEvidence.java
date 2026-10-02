package io.contexa.demo.work.approval.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ApprovalEvidence(
        UUID approvalId,
        UUID decisionId,
        boolean required,
        String status,
        String requester,
        String reviewer,
        String purpose,
        List<ApprovalTarget> targets,
        Instant decidedAt,
        Instant expiresAt,
        Instant observedAt,
        String source) {

    public ApprovalEvidence {
        targets = List.copyOf(targets);
    }

    public boolean usable() {
        return "APPROVED".equals(status);
    }
}
