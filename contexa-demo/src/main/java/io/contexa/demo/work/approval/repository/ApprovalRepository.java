package io.contexa.demo.work.approval.repository;

import io.contexa.demo.work.approval.dto.ApprovalActor;
import io.contexa.demo.work.approval.dto.ApprovalDecisionRecord;
import io.contexa.demo.work.approval.dto.ApprovalRequestRecord;

import java.util.List;
import java.util.UUID;

public interface ApprovalRepository {

    ApprovalRequestRecord request(UUID requestId, ApprovalRequestRecord record);

    ApprovalDecisionRecord decide(UUID requestId, ApprovalActor actor, ApprovalDecisionRecord record);

    List<ApprovalRequestRecord> list(ApprovalActor actor);

    ApprovalRequestRecord find(UUID id, UUID visitorId, UUID workspaceId);

    ApprovalDecisionRecord decision(UUID approvalId);
}
