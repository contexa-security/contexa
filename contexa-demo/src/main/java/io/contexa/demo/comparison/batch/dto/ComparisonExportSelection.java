package io.contexa.demo.comparison.batch.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.demo.work.export.dto.ExportResourceType;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;

public record ComparisonExportSelection(
        @NotNull ExportResourceType resourceType,
        @NotEmpty @Size(max = 50) List<@NotNull @Pattern(regexp = "[a-z0-9-]{1,60}") String> targetIds,
        UUID baselineApprovalId,
        UUID contexaApprovalId
) {

    @AssertTrue(message = "Both environments must use the same approval presence")
    @JsonIgnore
    public boolean isApprovalPair() {
        return (baselineApprovalId == null) == (contexaApprovalId == null);
    }

    @AssertTrue(message = "Export targets must be distinct")
    @JsonIgnore
    public boolean isDistinct() {
        return targetIds == null || targetIds.stream().distinct().count() == targetIds.size();
    }

    public UUID approvalFor(String arm) {
        return "baseline".equals(arm) ? baselineApprovalId : contexaApprovalId;
    }
}
