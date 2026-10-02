package io.contexa.demo.work.request.dto;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record DocumentReadInput(
        @NotNull WorkPurpose purpose,
        UUID approvalId) {
}
