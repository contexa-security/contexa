package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialVerificationExecutionStatus(
        String packageId,
        String aggregateRunId,
        String state,
        int progressPercent,
        boolean completed,
        boolean failed,
        Boolean recoverable,
        String failureReason,
        String retryInstruction,
        Integer revisionNo,
        Integer attemptNo,
        String failureStage,
        List<OfficialVerificationMetricExecutionStatus> metrics) {

    public OfficialVerificationExecutionStatus {
        metrics = metrics == null ? List.of() : List.copyOf(metrics);
    }

    public static OfficialVerificationExecutionStatus empty(String packageId) {
        return new OfficialVerificationExecutionStatus(
                packageId,
                null,
                "NOT_STARTED",
                0,
                false,
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                List.of());
    }
}
