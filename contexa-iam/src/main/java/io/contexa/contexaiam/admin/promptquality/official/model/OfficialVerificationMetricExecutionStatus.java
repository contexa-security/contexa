package io.contexa.contexaiam.admin.promptquality.official.model;

import java.time.Instant;

public record OfficialVerificationMetricExecutionStatus(
        String metricCode,
        int sequenceNo,
        String state,
        int progressPercent,
        Boolean recoverable,
        String failureReason,
        String retryInstruction,
        Instant startedAt,
        Instant completedAt) {
}

