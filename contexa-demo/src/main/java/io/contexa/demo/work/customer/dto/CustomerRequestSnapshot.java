package io.contexa.demo.work.customer.dto;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record CustomerRequestSnapshot(
        UUID requestId,
        WorkParticipant participant,
        CustomerSummary customer,
        List<String> assignedProjects,
        WorkPurpose declaredPurpose,
        String purposeSource,
        String businessSource,
        Instant observedAt,
        String action,
        ApprovalEvidence approval) implements WorkRequestSnapshot {

    public CustomerRequestSnapshot {
        assignedProjects = List.copyOf(assignedProjects);
    }

    @Override
    public String purpose() {
        return declaredPurpose.name();
    }

    @Override
    public BusinessResourceFacts resourceFacts() {
        return new BusinessResourceFacts(customer.id(), "CUSTOMER", customer.name().en(), customer.sensitivity(),
                customer.projectId(), customer.version(), List.of("READ", "EXPORT"));
    }
}
