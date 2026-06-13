package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialInspectionRunResponse(
        String aggregateRunId,
        String packageId,
        String operatorId,
        String generatedAt,
        boolean integrityValid,
        int passedMetrics,
        int totalMetrics,
        List<OfficialInspectionMetricResponse> metrics
) {
}
