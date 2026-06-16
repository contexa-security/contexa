package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record RuntimeEvidenceMetricResult(
        String metricCode,
        String officialRunId,
        String metricName,
        String groupName,
        double score,
        String state,
        String stateLabel,
        int passedChecks,
        int totalChecks,
        List<RuntimeEvidenceCheckResult> checks) {
}

