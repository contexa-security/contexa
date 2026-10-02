package io.contexa.demo.work.export.service.impl;

import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.ExportCatalog;
import io.contexa.demo.work.export.service.ExportRequestPreparation;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.project.repository.ProjectRepository;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import io.contexa.demo.work.request.service.support.AbstractRequestPreparation;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultExportRequestPreparation extends AbstractRequestPreparation implements ExportRequestPreparation {

    private final ExportCatalog catalog;

    public DefaultExportRequestPreparation(ExportCatalog catalog, ProjectRepository projects,
            BusinessRequestRepository requests, ApprovalUsageQuery approvals) {
        super(projects, requests, approvals);
        this.catalog = catalog;
    }

    @Override
    public ExportRequestSnapshot prepare(UUID requestId, WorkParticipant participant, ExportInput input) {
        List<ExportTarget> targets = catalog.resolve(input.resourceType(), input.targetIds());
        return persist(new ExportRequestSnapshot(requestId, participant, input.resourceType(), targets,
                assignedProjects(participant), input.purpose(), input.purpose().source(),
                "lab.business_document / lab.business_customer + lab.project_assignment", Instant.now(),
                approval(input.approvalId(), participant, input.purpose().name(),
                        targets.stream().map(ExportTarget::resource).toList())));
    }
}
