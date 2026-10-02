package io.contexa.demo.work.approval.dto;

import java.time.Instant;
import java.util.UUID;

public record ApprovalDecisionRecord(
        UUID id,
        UUID approvalId,
        UUID commandId,
        String reviewer,
        ApprovalVerdict verdict,
        String reason,
        Instant decidedAt,
        String inputSha256) {
}
