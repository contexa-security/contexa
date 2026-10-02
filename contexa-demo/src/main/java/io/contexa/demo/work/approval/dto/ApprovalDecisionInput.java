package io.contexa.demo.work.approval.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record ApprovalDecisionInput(
        @NotNull UUID commandId,
        @NotNull ApprovalVerdict verdict,
        @NotBlank @Size(max = 1000) String reason) {
}
