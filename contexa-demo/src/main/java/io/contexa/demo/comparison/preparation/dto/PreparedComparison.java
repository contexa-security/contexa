package io.contexa.demo.comparison.preparation.dto;

import java.time.Instant;
import java.util.UUID;

public record PreparedComparison(
        UUID id,
        UUID visitorId,
        UUID workspaceId,
        UUID commandId,
        Instant preparedAt,
        String inputSha256,
        String snapshotSha256,
        ComparisonPreparationSnapshot snapshot
) {
}
