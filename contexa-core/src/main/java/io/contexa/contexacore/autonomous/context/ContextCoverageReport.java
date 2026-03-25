package io.contexa.contexacore.autonomous.context;

import java.util.List;

public record ContextCoverageReport(
        ContextCoverageLevel level,
        List<String> availableFacts,
        List<String> missingCriticalFacts,
        List<String> remediationHints,
        List<String> confidenceWarnings,
        String summary) {
}
