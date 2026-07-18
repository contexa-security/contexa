package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.List;

public interface OfficialVerificationMetricSnapshotWriter {

    void insert(MetricSnapshotCommand command);

    record MetricSnapshotCommand(
            MetricIdentity identity,
            MetricAssessment assessment,
            OperatorNarrative narrative,
            List<String> issueIds,
            List<String> problemIds) {
    }

    record MetricIdentity(
            String aggregateRunId,
            String officialRunId,
            String packageId,
            String certificateId,
            String caseId,
            String metricCode,
            String metricName,
            String metricGroup) {
    }

    record MetricAssessment(
            double score,
            String state,
            String severity,
            int passedChecks,
            int totalChecks,
            int failedCheckCount) {
    }

    record OperatorNarrative(
            String title,
            String summary,
            String primaryFailureReason,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion) {
    }
}
