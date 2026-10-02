package io.contexa.demo.work.approval.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ApprovalRequestRecord(
        UUID id,
        UUID visitorId,
        UUID workspaceId,
        UUID commandId,
        String requester,
        ApprovalResourceType resourceType,
        List<ApprovalTarget> targets,
        ApprovalPurpose purpose,
        String reason,
        Instant requestedAt,
        Instant expiresAt,
        String inputSha256) {

    public ApprovalRequestRecord {
        targets = List.copyOf(targets);
    }
}
