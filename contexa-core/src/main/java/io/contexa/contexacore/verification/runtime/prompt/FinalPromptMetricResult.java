package io.contexa.contexacore.verification.runtime.prompt;

import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;

import java.util.List;

public record FinalPromptMetricResult(
        String metricCode,
        double score,
        int passedChecks,
        int totalChecks,
        String state,
        List<FinalPromptMetricCheck> checks
) {

    public FinalPromptMetricResult {
        checks = copyChecks(metricCode, checks);
    }

    public OfficialMetricEvaluationResult toOfficialMetricResult() {
        return new OfficialMetricEvaluationResult(
                metricCode,
                score,
                passedChecks,
                totalChecks,
                state,
                checks.stream().map(FinalPromptMetricCheck::toOfficialObservation).toList());
    }

    private static List<FinalPromptMetricCheck> copyChecks(String metricCode, List<FinalPromptMetricCheck> values) {
        if (values == null) {
            return List.of();
        }
        for (int index = 0; index < values.size(); index++) {
            if (values.get(index) == null) {
                throw new IllegalArgumentException("Final prompt metric result contains null check. metricCode="
                        + metricCode + ", checkIndex=" + index);
            }
        }
        return List.copyOf(values);
    }
}
