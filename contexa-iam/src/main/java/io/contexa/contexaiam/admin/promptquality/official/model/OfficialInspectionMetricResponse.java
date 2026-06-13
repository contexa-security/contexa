package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialInspectionMetricResponse(
        String metricCode,
        String metricLabel,
        String state,
        double score,
        int passedChecks,
        int totalChecks,
        String message,
        List<OfficialInspectionCheckResponse> checks
) {
}
