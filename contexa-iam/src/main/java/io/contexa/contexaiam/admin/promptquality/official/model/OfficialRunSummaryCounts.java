package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialRunSummaryCounts(
        int actualProblems,
        int blockedMetrics,
        int technicalTotal,
        int technicalPassed,
        int technicalFailed,
        int gateConditions,
        int inputReviewMetrics,
        int inputReadinessChecks,
        int criteriaFailed,
        int gateMetrics,
        int otherFailed) {

    public static OfficialRunSummaryCounts empty() {
        return new OfficialRunSummaryCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
