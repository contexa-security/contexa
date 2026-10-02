package io.contexa.demo.work.approval.service;

import io.contexa.demo.work.approval.dto.ApprovalActor;
import io.contexa.demo.work.approval.dto.ApprovalDecisionInput;
import io.contexa.demo.work.approval.dto.ApprovalRequestInput;
import io.contexa.demo.work.approval.dto.ApprovalView;

import java.util.List;
import java.util.UUID;

public interface ApprovalService {

    ApprovalView request(UUID requestId, ApprovalActor actor, ApprovalRequestInput input);

    ApprovalView decide(UUID requestId, UUID approvalId, ApprovalActor actor, ApprovalDecisionInput input);

    List<ApprovalView> list(ApprovalActor actor);

    ApprovalView find(UUID id, ApprovalActor actor);
}
