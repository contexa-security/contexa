package io.contexa.demo.work.approval.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

public record ApprovalRequestInput(
        @NotNull UUID commandId,
        @NotNull ApprovalResourceType resourceType,
        @NotEmpty @Size(max = 50) List<@NotBlank @Size(max = 60) String> targetIds,
        @NotNull ApprovalPurpose purpose,
        @NotBlank @Size(max = 1000) String reason,
        @Min(30) @Max(1800) int validForSeconds) {
}
