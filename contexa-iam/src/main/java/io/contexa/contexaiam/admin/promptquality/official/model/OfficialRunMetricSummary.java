package io.contexa.contexaiam.admin.promptquality.official.model;

import java.time.Instant;

public record OfficialRunMetricSummary(
        String metricCode,
        String metricName,
        String metricGroup,
        double score,
        String state,
        String severity,
        int passedChecks,
        int totalChecks,
        int failedCheckCount,
        String operatorTitle,
        String operatorSummary,
        String primaryFailureReason,
        String remediationOwner,
        String nextAction,
        String reverifyCriterion,
        String officialRunId,
        Instant createdAt) {
}
