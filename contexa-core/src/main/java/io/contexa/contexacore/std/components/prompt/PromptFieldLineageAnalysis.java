package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PromptFieldLineageAnalysis(
        List<PromptFieldSnapshot> rawUserFields,
        List<PromptFieldSnapshot> finalUserFields,
        List<PromptFieldDiffRecord> fieldDiffs,
        int missingInFinalCount,
        int changedCount,
        int addedInFinalCount,
        int compactedMarkerCount,
        int truncatedMarkerCount) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptRawUserFieldCount", rawUserFields.size());
        metadata.put("promptFinalUserFieldCount", finalUserFields.size());
        metadata.put("promptUserFieldDiffCount", fieldDiffs.size());
        metadata.put("promptUserFieldLossCount", missingInFinalCount);
        metadata.put("promptUserFieldChangedCount", changedCount);
        metadata.put("promptUserFieldAddedCount", addedInFinalCount);
        metadata.put("promptUserFieldCompactedMarkerCount", compactedMarkerCount);
        metadata.put("promptUserFieldTruncatedMarkerCount", truncatedMarkerCount);
        metadata.put("promptRawUserFieldLedger", rawUserFields.stream()
                .map(PromptFieldSnapshot::toMetadataMap)
                .toList());
        metadata.put("promptFinalUserFieldLedger", finalUserFields.stream()
                .map(PromptFieldSnapshot::toMetadataMap)
                .toList());
        metadata.put("promptUserFieldDiffLedger", fieldDiffs.stream()
                .map(PromptFieldDiffRecord::toMetadataMap)
                .toList());
        metadata.put("promptUserFieldLineageSummary", summary());
        return metadata;
    }

    private Map<String, Object> summary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("rawUserFieldCount", rawUserFields.size());
        summary.put("finalUserFieldCount", finalUserFields.size());
        summary.put("diffCount", fieldDiffs.size());
        summary.put("missingInFinalCount", missingInFinalCount);
        summary.put("changedCount", changedCount);
        summary.put("addedInFinalCount", addedInFinalCount);
        summary.put("compactedMarkerCount", compactedMarkerCount);
        summary.put("truncatedMarkerCount", truncatedMarkerCount);
        return summary;
    }
}
