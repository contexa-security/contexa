package io.contexa.demo.comparison.preparation.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.comparison.batch.dto.ComparisonExportSelection;
import io.contexa.demo.experience.journey.dto.JourneyStepReference;
import io.contexa.demo.comparison.approval.dto.ComparisonApprovalReferences;
import jakarta.validation.Valid;
import io.contexa.demo.work.shared.dto.WorkPurpose;
import io.contexa.demo.work.download.dto.DocumentLanguage;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

public record PreparationCommand(
        @NotNull UUID commandId,
        @Pattern(regexp = "[a-z0-9-]{1,100}") String documentId,
        @NotBlank @Pattern(regexp = "[a-zA-Z0-9._@-]{1,100}") String requestedAccount,
        @NotNull WorkPurpose purpose,
        @Pattern(regexp = "[a-z0-9-]{1,100}") String customerId,
        @Pattern(regexp = "READ|DOWNLOAD|EXPORT") String operation,
        DocumentLanguage language,
        @JsonInclude(JsonInclude.Include.NON_NULL) UUID parentRunId,
        @Valid @JsonInclude(JsonInclude.Include.NON_NULL) ComparisonExportSelection exportSelection,
        @Valid @JsonInclude(JsonInclude.Include.NON_NULL) JourneyStepReference journeyStep,
        @Valid @JsonInclude(JsonInclude.Include.NON_NULL) ComparisonApprovalReferences approvalReferences,
        @JsonInclude(JsonInclude.Include.NON_NULL) UUID historyReportId
) {

    @AssertTrue(message = "Select exactly one business resource")
    @JsonIgnore
    public boolean isSingleResource() {
        return (documentId != null ? 1 : 0) + (customerId != null ? 1 : 0) + (exportSelection != null ? 1 : 0) == 1;
    }

    @AssertTrue(message = "File language is required only for document download")
    @JsonIgnore
    public boolean isValidOperation() {
        if (exportSelection != null) {
            return "EXPORT".equals(operation) && language != null && approvalReferences == null;
        }
        return "DOWNLOAD".equals(operation) ? documentId != null && customerId == null && language != null
                : !"EXPORT".equals(operation) && language == null;
    }
}
