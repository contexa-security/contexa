package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialRunLedgerConsistency(
        int expectedMetricCount,
        int actualRunCount,
        boolean metricCountMatched,
        int totalCheckCount,
        int declaredCheckCount,
        int storedCheckRowCount,
        boolean checkCountMatched,
        int missingSourceCheckCount,
        int abstractSourceCheckCount,
        int rawArtifactRunCount,
        int factBackedRunCount,
        boolean aggregateRunIdPresent,
        boolean readyForIssueResolution,
        List<String> warnings) {
}

