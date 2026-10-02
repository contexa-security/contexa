package io.contexa.demo.work.approval.service.impl;

import io.contexa.demo.work.approval.dto.ApprovalDecisionRecord;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.approval.dto.ApprovalRequestRecord;
import io.contexa.demo.work.approval.dto.ApprovalVerdict;
import io.contexa.demo.work.approval.repository.ApprovalRepository;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.approval.service.WorkApprovalException;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultApprovalUsageQuery implements ApprovalUsageQuery {

    private static final Set<String> REQUIRED_PURPOSES = Set.of("APPROVED_BULK_DELIVERY", "EMERGENCY_MAINTENANCE");
    private static final String SOURCE = "lab.business_approval + lab.business_approval_decision";

    private final ApprovalRepository approvals;

    public DefaultApprovalUsageQuery(ApprovalRepository approvals) {
        this.approvals = approvals;
    }

    @Override
    public ApprovalEvidence inspect(UUID approvalId, WorkParticipant participant, String purpose,
            List<BusinessResourceFacts> resources) {
        boolean required = REQUIRED_PURPOSES.contains(purpose);
        if (approvalId == null) {
            return unavailable(null, required, "NOT_LINKED", Instant.now());
        }
        ApprovalRequestRecord request = approvals.find(approvalId, participant.visitorId(), participant.workspaceId());
        if (request == null || !request.requester().equals(participant.username())) {
            return unavailable(approvalId, required, "UNAVAILABLE", Instant.now());
        }
        ApprovalDecisionRecord decision = approvals.decision(approvalId);
        Instant observedAt = Instant.now();
        String status = status(request, decision, purpose, resources, observedAt);
        return new ApprovalEvidence(approvalId, decision == null ? null : decision.id(), required, status,
                request.requester(), decision == null ? null : decision.reviewer(), request.purpose().name(),
                request.targets(), decision == null ? null : decision.decidedAt(), request.expiresAt(), observedAt,
                SOURCE);
    }

    @Override
    public void requireUsable(ApprovalEvidence evidence) {
        if ((evidence.required() || evidence.approvalId() != null) && !evidence.usable()) {
            throw new WorkApprovalException(evidence.status());
        }
    }

    private String status(ApprovalRequestRecord request, ApprovalDecisionRecord decision, String purpose,
            List<BusinessResourceFacts> resources, Instant observedAt) {
        if (decision != null && decision.verdict() == ApprovalVerdict.REJECTED) {
            return "REJECTED";
        }
        if (!observedAt.isBefore(request.expiresAt())) {
            return "EXPIRED";
        }
        if (!request.purpose().name().equals(purpose)) {
            return "PURPOSE_MISMATCH";
        }
        boolean covered = !resources.isEmpty() && resources.stream().allMatch(resource ->
                request.resourceType().name().equals(resource.type()) && request.targets().stream().anyMatch(target ->
                        target.id().equals(resource.id()) && target.version() == resource.version()
                                && target.projectId().equals(resource.projectId())));
        if (!covered) {
            return "SCOPE_MISMATCH";
        }
        return decision == null ? "PENDING" : "APPROVED";
    }

    private ApprovalEvidence unavailable(UUID approvalId, boolean required, String status, Instant observedAt) {
        return new ApprovalEvidence(approvalId, null, required, status, null, null, null, List.of(),
                null, null, observedAt, SOURCE);
    }
}
