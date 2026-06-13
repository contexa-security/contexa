package io.contexa.contexacore.verification.runtime;

public record OfficialVerificationScenarioDefinition(
        String metricCode,
        String title,
        String executionPath,
        boolean ready,
        String description) {
}
