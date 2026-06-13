package io.contexa.contexacore.verification.runtime;

import java.time.Instant;
import java.util.Map;

public record OfficialVerificationRunRecord(
        String runId,
        String metricCode,
        String executionPath,
        String state,
        String requestedBy,
        Instant requestedAt,
        Instant startedAt,
        Instant completedAt,
        String message,
        Map<String, String> evidenceReferences) {

    public OfficialVerificationRunSummary toSummary() {
        return new OfficialVerificationRunSummary(
                runId,
                metricCode,
                executionPath,
                state,
                requestedBy,
                requestedAt,
                completedAt,
                message
        );
    }
}
