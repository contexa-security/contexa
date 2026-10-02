package io.contexa.demo.comparison.run.dto;

import java.time.Instant;
import java.util.UUID;

public record RunRecord(
        UUID id,
        UUID visitorId,
        UUID workspaceId,
        UUID commandId,
        UUID coordinatorInstanceId,
        Instant createdAt,
        Instant dispatchDeadline,
        String inputSha256,
        String manifestSha256,
        RunManifest manifest,
        String state
) {
}
