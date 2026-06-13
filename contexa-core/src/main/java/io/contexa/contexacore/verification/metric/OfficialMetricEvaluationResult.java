package io.contexa.contexacore.verification.metric;

import java.util.List;

public record OfficialMetricEvaluationResult(
        String metricCode,
        double score,
        int passedChecks,
        int totalChecks,
        String state,
        List<OfficialMetricCheckObservation> checks
) {
    public OfficialMetricEvaluationResult {
        metricCode = metricCode == null || metricCode.isBlank() ? "UNKNOWN_METRIC" : metricCode.trim();
        state = state == null || state.isBlank() ? "missing" : state.trim();
        checks = copyChecks(metricCode, checks);
    }

    private static List<OfficialMetricCheckObservation> copyChecks(
            String metricCode,
            List<OfficialMetricCheckObservation> values) {
        if (values == null) {
            return List.of();
        }
        for (int index = 0; index < values.size(); index++) {
            if (values.get(index) == null) {
                throw new IllegalArgumentException("Official metric evaluation result contains null check. metricCode="
                        + metricCode + ", checkIndex=" + index);
            }
        }
        return List.copyOf(values);
    }
}
