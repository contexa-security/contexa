package io.contexa.contexaiam.admin.promptquality.official.domain;

public record ContextEvidenceFinding(
        String metricCode,
        String severity,
        String message,
        String evidencePath,
        String nextAction) {
}
