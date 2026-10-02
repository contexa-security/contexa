package io.contexa.demo.work.customer.dto;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record CustomerReadInput(
        @NotNull WorkPurpose purpose,
        UUID approvalId) {
}
