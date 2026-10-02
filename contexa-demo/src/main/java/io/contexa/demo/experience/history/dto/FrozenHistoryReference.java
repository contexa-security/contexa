package io.contexa.demo.experience.history.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record FrozenHistoryReference(
        UUID reportId,
        String reportSha256,
        UUID sourceRunId,
        String sourceManifestSha256,
        Instant capturedAt,
        String account,
        List<HistoryOrigin> origins,
        String applicationCompatibility,
        String currentHistoryState,
        List<String> limitations
) {
}
