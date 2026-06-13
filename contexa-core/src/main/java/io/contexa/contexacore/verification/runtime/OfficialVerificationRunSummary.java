package io.contexa.contexacore.verification.runtime;

import java.time.Instant;

public record OfficialVerificationRunSummary(
        String runId,
        String metricCode,
        String executionPath,
        String state,
        String requestedBy,
        Instant requestedAt,
        Instant completedAt,
        String message) {
}
