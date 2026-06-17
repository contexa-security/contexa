package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record RuntimeEvidencePromptConsistencyResult(
        String state,
        String stateLabel,
        boolean passed,
        boolean blocking,
        List<RuntimeEvidenceCheckResult> checks,
        List<String> findings,
        List<String> nextActions) {

    public static RuntimeEvidencePromptConsistencyResult empty() {
        return new RuntimeEvidencePromptConsistencyResult(
                "REVIEW_REQUIRED",
                "Review required",
                false,
                false,
                List.of(),
                List.of(),
                List.of());
    }
}
