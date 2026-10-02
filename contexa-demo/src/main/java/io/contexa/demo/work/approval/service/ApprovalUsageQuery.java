package io.contexa.demo.work.approval.service;

import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;

import java.util.List;
import java.util.UUID;

public interface ApprovalUsageQuery {

    ApprovalEvidence inspect(UUID approvalId, WorkParticipant participant, String purpose,
            List<BusinessResourceFacts> resources);

    void requireUsable(ApprovalEvidence evidence);
}
