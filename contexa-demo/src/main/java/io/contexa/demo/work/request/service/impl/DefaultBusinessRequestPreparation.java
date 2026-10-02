package io.contexa.demo.work.request.service.impl;

import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.catalog.service.WorkCatalog;
import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.project.repository.ProjectRepository;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.request.dto.DocumentOperation;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import io.contexa.demo.work.request.service.BusinessRequestPreparation;
import io.contexa.demo.work.request.service.support.AbstractRequestPreparation;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultBusinessRequestPreparation extends AbstractRequestPreparation implements BusinessRequestPreparation {

    private final WorkCatalog catalog;

    public DefaultBusinessRequestPreparation(WorkCatalog catalog, ProjectRepository projects,
            BusinessRequestRepository requests, ApprovalUsageQuery approvals) {
        super(projects, requests, approvals);
        this.catalog = catalog;
    }

    @Override
    public BusinessRequestSnapshot prepare(UUID requestId, WorkParticipant participant, String documentId,
            WorkPurpose purpose, DocumentOperation operation, UUID approvalId) {
        DocumentSummary document = catalog.document(documentId);
        Instant observedAt = Instant.now();
        BusinessResourceFacts resource = new BusinessResourceFacts(document.id(), "DOCUMENT", document.title().en(),
                document.sensitivity(), document.projectId(), document.version(), List.of("READ", "DOWNLOAD"));
        return persist(new BusinessRequestSnapshot(requestId, participant, document, assignedProjects(participant),
                purpose, purpose.source(), "lab.business_document + lab.project_assignment", observedAt, operation,
                approval(approvalId, participant, purpose.name(), resource)));
    }
}
