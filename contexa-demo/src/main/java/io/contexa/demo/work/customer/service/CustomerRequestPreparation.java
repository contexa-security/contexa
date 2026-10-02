package io.contexa.demo.work.customer.service;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;
import io.contexa.demo.work.participant.dto.WorkParticipant;

import java.util.UUID;

public interface CustomerRequestPreparation {

    CustomerRequestSnapshot prepare(UUID requestId, WorkParticipant participant, String customerId,
            WorkPurpose purpose, UUID approvalId);
}
