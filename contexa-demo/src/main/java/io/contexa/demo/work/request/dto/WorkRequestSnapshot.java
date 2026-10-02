package io.contexa.demo.work.request.dto;

import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface WorkRequestSnapshot {

    UUID requestId();

    WorkParticipant participant();

    List<String> assignedProjects();

    String purpose();

    String purposeSource();

    String businessSource();

    Instant observedAt();

    String action();

    BusinessResourceFacts resourceFacts();

    ApprovalEvidence approval();
}
