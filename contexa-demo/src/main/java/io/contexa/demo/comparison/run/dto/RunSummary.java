package io.contexa.demo.comparison.run.dto;

import io.contexa.demo.work.shared.dto.WorkPurpose;
import java.time.Instant;
import java.util.UUID;

public record RunSummary(
        UUID id,
        Instant createdAt,
        String state,
        String planKind,
        String path,
        String account,
        WorkPurpose purpose,
        String manifestSha256
) {
}
