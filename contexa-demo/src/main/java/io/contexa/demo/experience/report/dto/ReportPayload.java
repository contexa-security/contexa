package io.contexa.demo.experience.report.dto;

import io.contexa.demo.comparison.run.dto.RunView;
import java.time.Instant;
import java.util.List;

public record ReportPayload(
        String version,
        Instant capturedAt,
        RunView execution,
        List<ReportSource> sources,
        List<String> limitations,
        String reviewState,
        String reproduction
) {
}
