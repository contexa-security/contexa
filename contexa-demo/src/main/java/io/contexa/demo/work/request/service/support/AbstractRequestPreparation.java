package io.contexa.demo.work.request.service.support;

import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.project.repository.ProjectRepository;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;

import java.util.List;
import java.util.UUID;

public abstract class AbstractRequestPreparation {

    private final ProjectRepository projects;
    private final BusinessRequestRepository requests;
    private final ApprovalUsageQuery approvals;

    protected AbstractRequestPreparation(ProjectRepository projects, BusinessRequestRepository requests,
            ApprovalUsageQuery approvals) {
        this.projects = projects;
        this.requests = requests;
        this.approvals = approvals;
    }

    protected List<String> assignedProjects(WorkParticipant participant) {
        return projects.assignedProjects(participant.username());
    }

    protected ApprovalEvidence approval(UUID approvalId, WorkParticipant participant, String purpose,
            BusinessResourceFacts resource) {
        return approval(approvalId, participant, purpose, List.of(resource));
    }

    protected ApprovalEvidence approval(UUID approvalId, WorkParticipant participant, String purpose,
            List<BusinessResourceFacts> resources) {
        return approvals.inspect(approvalId, participant, purpose, resources);
    }

    protected <T extends WorkRequestSnapshot> T persist(T snapshot) {
        requests.append(snapshot);
        return snapshot;
    }
}
