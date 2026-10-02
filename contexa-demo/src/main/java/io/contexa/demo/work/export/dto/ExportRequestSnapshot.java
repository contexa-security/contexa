package io.contexa.demo.work.export.dto;

import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import io.contexa.demo.work.shared.dto.WorkPurpose;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public record ExportRequestSnapshot(
        UUID requestId,
        WorkParticipant participant,
        ExportResourceType resourceType,
        List<ExportTarget> targets,
        List<String> assignedProjects,
        WorkPurpose declaredPurpose,
        String purposeSource,
        String businessSource,
        Instant observedAt,
        ApprovalEvidence approval) implements WorkRequestSnapshot {

    public ExportRequestSnapshot {
        targets = List.copyOf(targets);
        assignedProjects = List.copyOf(assignedProjects);
    }

    @Override
    public String purpose() {
        return declaredPurpose.name();
    }

    @Override
    public String action() {
        return "EXPORT";
    }

    @Override
    public BusinessResourceFacts resourceFacts() {
        String projects = targets.stream().map(target -> target.resource().projectId()).distinct().sorted()
                .collect(Collectors.joining(","));
        String sensitivity = targets.stream().anyMatch(target -> "CONFIDENTIAL".equals(target.resource().sensitivity()))
                ? "CONFIDENTIAL" : "INTERNAL";
        String label = resourceType.name() + " export; target count=" + targets.size() + "; projects=" + projects;
        return new BusinessResourceFacts("export:" + requestId, "EXPORT", label, sensitivity, projects, 1,
                List.of("EXPORT"));
    }
}
