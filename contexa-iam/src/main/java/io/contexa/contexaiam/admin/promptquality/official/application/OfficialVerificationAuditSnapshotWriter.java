package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.List;
import java.util.Map;

public interface OfficialVerificationAuditSnapshotWriter {

    void record(AuditSnapshotCommand command);

    record AuditSnapshotCommand(
            String tenantId,
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String state,
            String stateLabel,
            int totalMetricCount,
            int failedMetricCount,
            boolean certificateIssued,
            String promptHash,
            String contextHash,
            List<String> blockingFindings,
            List<String> nextActions,
            Map<String, Object> payload,
            String operatorId) {
    }
}
