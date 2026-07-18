package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationPromptLineageWriter {

    void insert(Command command);

    record Command(
            String packageId,
            String aggregateRunId,
            String promptHash,
            String contextHash,
            String systemPromptHash,
            String userPromptHash,
            String rawPromptHash,
            String rawSystemPromptHash,
            String rawUserPromptHash,
            String promptBudgetProfile,
            Boolean compressionApplied,
            String transformationMode,
            Boolean rawTruthParity,
            Integer rawUserFieldCount,
            Integer finalUserFieldCount,
            Integer fieldDiffCount,
            Integer fieldLossCount,
            Integer fieldChangedCount,
            Integer fieldAddedCount,
            Integer compactedMarkerCount,
            Integer truncatedMarkerCount,
            String lineageSummaryJson) {
    }
}
