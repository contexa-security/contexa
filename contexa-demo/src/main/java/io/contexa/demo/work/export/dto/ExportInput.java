package io.contexa.demo.work.export.dto;

import io.contexa.demo.work.download.dto.DocumentLanguage;
import io.contexa.demo.work.shared.dto.WorkPurpose;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

public record ExportInput(
        @NotNull UUID commandId,
        @NotNull ExportResourceType resourceType,
        @NotEmpty @Size(max = 50) List<@NotBlank @Size(max = 60) String> targetIds,
        @NotNull WorkPurpose purpose,
        @NotNull DocumentLanguage language,
        UUID approvalId) {

    public ExportInput {
        targetIds = targetIds == null ? null : List.copyOf(targetIds);
    }
}
