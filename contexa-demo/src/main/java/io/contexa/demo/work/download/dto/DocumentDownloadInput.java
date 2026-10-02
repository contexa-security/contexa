package io.contexa.demo.work.download.dto;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record DocumentDownloadInput(
        @NotNull UUID commandId,
        @NotNull WorkPurpose purpose,
        @NotNull DocumentLanguage language,
        UUID approvalId) {
}
