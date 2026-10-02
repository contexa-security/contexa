package io.contexa.demo.work.request.dto;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record BusinessRequestSnapshot(
        UUID requestId,
        WorkParticipant participant,
        DocumentSummary document,
        List<String> assignedProjects,
        WorkPurpose declaredPurpose,
        String purposeSource,
        String businessSource,
        Instant observedAt,
        DocumentOperation operation,
        ApprovalEvidence approval) implements WorkRequestSnapshot {

    public BusinessRequestSnapshot {
        assignedProjects = List.copyOf(assignedProjects);
        operation = operation == null ? DocumentOperation.READ : operation;
    }

    @Override
    public String purpose() {
        return declaredPurpose.name();
    }

    @Override
    public String action() {
        return operation.name();
    }

    @Override
    public BusinessResourceFacts resourceFacts() {
        return new BusinessResourceFacts(document.id(), "DOCUMENT", document.title().en(), document.sensitivity(),
                document.projectId(), document.version(), List.of("READ", "DOWNLOAD"));
    }
}
