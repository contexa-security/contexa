package io.contexa.contexaiam.aiam.protocol.response;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record ApprovalResponseDto(
        @NotNull(message = "Approval decision cannot be null")
        Boolean approved,
        @NotEmpty(message = "Comment cannot be empty")
        String comment
) {}