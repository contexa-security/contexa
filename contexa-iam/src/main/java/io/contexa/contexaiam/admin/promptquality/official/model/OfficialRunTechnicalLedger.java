package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;
import java.util.Map;

public record OfficialRunTechnicalLedger(
        String packageId,
        String aggregateRunId,
        int totalRunCount,
        boolean truncated,
        List<Run> runs) {

    public record Run(
            String metricCode,
            String officialRunId,
            String state,
            int passedChecks,
            int totalChecks,
            Map<String, String> requestFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            Map<String, Object> rawEvidence) {
    }

    public OfficialRunTechnicalLedger {
        runs = runs == null ? List.of() : List.copyOf(runs);
    }
}