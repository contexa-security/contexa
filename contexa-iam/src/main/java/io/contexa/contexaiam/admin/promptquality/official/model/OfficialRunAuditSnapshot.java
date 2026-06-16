package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialRunAuditSnapshot(
        String snapshotId,
        String packageId,
        String aggregateRunId,
        String createdAt,
        String state,
        String stateLabel,
        int totalMetricCount,
        int failedMetricCount,
        boolean certificateIssued,
        String certificateId,
        String caseId,
        String promptHash,
        String contextHash,
        List<String> blockingFindings,
        List<String> nextActions,
        boolean persisted,
        String payloadJson) {

    public OfficialRunAuditSnapshot {
        blockingFindings = blockingFindings == null ? List.of() : List.copyOf(blockingFindings);
        nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
    }
}

