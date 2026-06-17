package io.contexa.contexaiam.admin.promptquality.official.model;

import java.time.Instant;

public record OfficialRunPackageListItem(
        String packageId,
        String aggregateRunId,
        String finalDecision,
        boolean blocked,
        String blockReasonSummary,
        int expectedMetricCount,
        int actualMetricCount,
        int passedMetricCount,
        int failedMetricCount,
        String certificateId,
        String caseId,
        String promptHash,
        String contextHash,
        String contextHashState,
        String resourceTemplateId,
        String actualResourceId,
        String resourceUrlTemplate,
        String actualRequestPath,
        String httpMethod,
        Instant createdAt) {
}
