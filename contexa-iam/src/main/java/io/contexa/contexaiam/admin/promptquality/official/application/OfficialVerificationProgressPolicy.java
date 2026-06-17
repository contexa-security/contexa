package io.contexa.contexaiam.admin.promptquality.official.application;

final class OfficialVerificationProgressPolicy {

    static final int REQUEST_ACCEPTED = 5;
    static final int LOCK_ACQUIRED = 15;
    static final int EVIDENCE_LOADED = 25;
    static final int CONSISTENCY_CHECKED = 35;
    static final int FINAL_PROMPT_PREFLIGHT = 40;
    static final int METRICS_RUNNING = 45;
    static final int METRICS_COMPLETED_MAX = 84;
    static final int SNAPSHOT_WRITING = 85;
    static final int COMPLETED = 100;

    private OfficialVerificationProgressPolicy() {
    }

    static int metricProgress(int completedMetricCount, int totalMetricCount) {
        if (totalMetricCount <= 0) {
            return METRICS_RUNNING;
        }
        int completed = Math.max(0, Math.min(completedMetricCount, totalMetricCount));
        int span = METRICS_COMPLETED_MAX - METRICS_RUNNING;
        return bound(METRICS_RUNNING + (int) Math.round((completed * 1.0 * span) / totalMetricCount));
    }

    static int failureProgress(int currentProgress) {
        return Math.max(REQUEST_ACCEPTED, Math.min(SNAPSHOT_WRITING, bound(currentProgress)));
    }

    static int bound(int progressPercent) {
        return Math.max(0, Math.min(COMPLETED, progressPercent));
    }
}
