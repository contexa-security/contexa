package io.contexa.demo.comparison.approval.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record ComparisonApprovalReferences(
        @NotNull UUID baselineApprovalId,
        @NotNull UUID contexaApprovalId
) {

    public UUID approvalFor(String arm) {
        return "baseline".equals(arm) ? baselineApprovalId : contexaApprovalId;
    }
}
