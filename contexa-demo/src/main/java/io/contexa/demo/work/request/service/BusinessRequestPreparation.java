package io.contexa.demo.work.request.service;

import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.request.dto.DocumentOperation;

import java.util.UUID;

public interface BusinessRequestPreparation {

    default BusinessRequestSnapshot prepare(UUID requestId, WorkParticipant participant, String documentId,
            WorkPurpose purpose, UUID approvalId) {
        return prepare(requestId, participant, documentId, purpose, DocumentOperation.READ, approvalId);
    }

    BusinessRequestSnapshot prepare(UUID requestId, WorkParticipant participant, String documentId,
            WorkPurpose purpose, DocumentOperation operation, UUID approvalId);
}
