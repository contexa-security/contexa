package io.contexa.demo.work.approval.service.impl;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.dto.ApprovalActor;
import io.contexa.demo.work.approval.dto.ApprovalDecisionInput;
import io.contexa.demo.work.approval.dto.ApprovalDecisionRecord;
import io.contexa.demo.work.approval.dto.ApprovalRequestInput;
import io.contexa.demo.work.approval.dto.ApprovalRequestRecord;
import io.contexa.demo.work.approval.dto.ApprovalVerdict;
import io.contexa.demo.work.approval.dto.ApprovalView;
import io.contexa.demo.work.approval.repository.ApprovalRepository;
import io.contexa.demo.work.approval.service.ApprovalService;
import io.contexa.demo.work.approval.service.ApprovalTargetQuery;
import io.contexa.demo.work.project.repository.ProjectRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultApprovalService implements ApprovalService {

    private final ApprovalRepository approvals;
    private final ApprovalTargetQuery targets;
    private final ProjectRepository projects;
    private final DocumentCodec documents;

    public DefaultApprovalService(ApprovalRepository approvals, ApprovalTargetQuery targets,
            ProjectRepository projects, DocumentCodec documents) {
        this.approvals = approvals;
        this.targets = targets;
        this.projects = projects;
        this.documents = documents;
    }

    @Override
    public ApprovalView request(UUID requestId, ApprovalActor actor, ApprovalRequestInput input) {
        Instant now = Instant.now();
        var participant = actor.participant();
        ApprovalRequestRecord proposed = new ApprovalRequestRecord(UUID.randomUUID(), participant.visitorId(),
                participant.workspaceId(), input.commandId(), participant.username(), input.resourceType(),
                targets.resolve(input.resourceType(), input.targetIds()), input.purpose(), input.reason().strip(),
                now, now.plusSeconds(input.validForSeconds()), documents.hash(documents.write(input)));
        return view(approvals.request(requestId, proposed), actor);
    }

    @Override
    public ApprovalView decide(UUID requestId, UUID approvalId, ApprovalActor actor, ApprovalDecisionInput input) {
        ApprovalRequestRecord request = owned(approvalId, actor);
        if (!reviewAuthority(request, actor)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "APPROVAL_REVIEW_NOT_ALLOWED");
        }
        ApprovalDecisionRecord proposed = new ApprovalDecisionRecord(UUID.randomUUID(), approvalId, input.commandId(),
                actor.participant().username(), input.verdict(), input.reason().strip(), Instant.now(),
                documents.hash(documents.write(input)));
        approvals.decide(requestId, actor, proposed);
        return view(request, actor);
    }

    @Override
    public List<ApprovalView> list(ApprovalActor actor) {
        return approvals.list(actor).stream().map(request -> view(request, actor)).toList();
    }

    @Override
    public ApprovalView find(UUID id, ApprovalActor actor) {
        return view(owned(id, actor), actor);
    }

    private ApprovalRequestRecord owned(UUID id, ApprovalActor actor) {
        var participant = actor.participant();
        ApprovalRequestRecord request = approvals.find(id, participant.visitorId(), participant.workspaceId());
        if (request == null || (!actor.administrator() && !request.requester().equals(participant.username()))) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return request;
    }

    private ApprovalView view(ApprovalRequestRecord request, ApprovalActor actor) {
        ApprovalDecisionRecord decision = approvals.decision(request.id());
        Instant now = Instant.now();
        String status;
        if (decision != null && decision.verdict() == ApprovalVerdict.REJECTED) {
            status = "REJECTED";
        } else if (!now.isBefore(request.expiresAt())) {
            status = "EXPIRED";
        } else {
            status = decision == null ? "PENDING" : "APPROVED";
        }
        return new ApprovalView(request, decision, status, now,
                "PENDING".equals(status) && reviewAuthority(request, actor));
    }

    private boolean reviewAuthority(ApprovalRequestRecord request, ApprovalActor actor) {
        if (!actor.administrator() || request.requester().equals(actor.participant().username())) {
            return false;
        }
        List<String> assigned = projects.assignedProjects(actor.participant().username());
        return request.targets().stream().allMatch(target -> assigned.contains(target.projectId()));
    }
}
