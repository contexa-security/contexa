package io.contexa.demo.comparison.preparation.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.work.shared.dto.WorkPurpose;
import java.util.UUID;
import io.contexa.demo.comparison.batch.dto.ComparisonExportSelection;
import io.contexa.demo.experience.journey.dto.JourneyStepReference;
import io.contexa.demo.comparison.approval.dto.ComparisonApprovalReferences;

public record ComparisonRequestPlan(
        String kind,
        String method,
        String path,
        String requestedAccount,
        WorkPurpose purpose,
        int requestsPerArm,
        @JsonInclude(JsonInclude.Include.NON_NULL) ComparisonFileRequest fileRequest,
        @JsonInclude(JsonInclude.Include.NON_NULL) UUID parentRunId,
        @JsonInclude(JsonInclude.Include.NON_NULL) ComparisonExportSelection exportSelection,
        @JsonInclude(JsonInclude.Include.NON_NULL) JourneyStepReference journeyStep,
        @JsonInclude(JsonInclude.Include.NON_NULL) ComparisonApprovalReferences approvalReferences,
        @JsonInclude(JsonInclude.Include.NON_NULL) UUID historyReportId
) {

    public ComparisonRequestPlan withParent(UUID sourceRunId) {
        return new ComparisonRequestPlan(kind, method, path, requestedAccount, purpose, requestsPerArm,
                fileRequest, sourceRunId, exportSelection, journeyStep, approvalReferences, historyReportId);
    }

    public UUID approvalFor(String arm) {
        return exportSelection != null ? exportSelection.approvalFor(arm)
                : approvalReferences != null ? approvalReferences.approvalFor(arm) : null;
    }
}
