package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialRunAttemptSummary(
        String aggregateRunId,
        String packageId,
        int attemptNo,
        String startedAt,
        String completedAt,
        int totalRunCount,
        int passedRunCount,
        int failedRunCount,
        String state,
        String stateLabel,
        boolean latest) {
}

