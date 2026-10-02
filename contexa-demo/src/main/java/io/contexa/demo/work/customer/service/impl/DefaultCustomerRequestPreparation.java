package io.contexa.demo.work.customer.service.impl;

import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;
import io.contexa.demo.work.customer.dto.CustomerSummary;
import io.contexa.demo.work.customer.service.CustomerCatalog;
import io.contexa.demo.work.customer.service.CustomerRequestPreparation;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.project.repository.ProjectRepository;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import io.contexa.demo.work.request.service.support.AbstractRequestPreparation;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultCustomerRequestPreparation extends AbstractRequestPreparation implements CustomerRequestPreparation {

    private final CustomerCatalog customers;

    public DefaultCustomerRequestPreparation(CustomerCatalog customers, ProjectRepository projects,
            BusinessRequestRepository requests, ApprovalUsageQuery approvals) {
        super(projects, requests, approvals);
        this.customers = customers;
    }

    @Override
    public CustomerRequestSnapshot prepare(UUID requestId, WorkParticipant participant, String customerId,
            WorkPurpose purpose, UUID approvalId) {
        CustomerSummary customer = customers.customer(customerId);
        Instant observedAt = Instant.now();
        BusinessResourceFacts resource = new BusinessResourceFacts(customer.id(), "CUSTOMER", customer.name().en(),
                customer.sensitivity(), customer.projectId(), customer.version(), List.of("READ", "EXPORT"));
        return persist(new CustomerRequestSnapshot(requestId, participant, customer, assignedProjects(participant),
                purpose, purpose.source(), "lab.business_customer + lab.customer_activity + lab.project_assignment",
                observedAt, "READ", approval(approvalId, participant, purpose.name(), resource)));
    }
}
