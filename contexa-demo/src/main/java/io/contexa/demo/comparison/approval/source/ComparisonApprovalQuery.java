package io.contexa.demo.comparison.approval.source;

import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.participant.dto.WorkParticipant;

public interface ComparisonApprovalQuery {

    ApprovalEvidence capture(ComparisonRequestPlan plan, String resourceId, WorkParticipant participant);
}
