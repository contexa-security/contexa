package io.contexa.contexacore.autonomous.context.model;

import java.util.List;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageLevel;

public record ContextCoverageReport(
        ContextCoverageLevel level,
        List<String> availableFacts,
        List<String> missingCriticalFacts,
        List<String> remediationHints,
        List<String> confidenceWarnings,
        String summary) {
}
