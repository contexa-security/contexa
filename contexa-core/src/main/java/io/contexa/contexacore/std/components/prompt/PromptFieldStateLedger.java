package io.contexa.contexacore.std.components.prompt;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PromptFieldStateLedger(
        List<PromptFieldStateRecord> records,
        int sourceFieldCount,
        int rawUserFieldCount,
        int finalUserFieldCount,
        int projectionDiffCount,
        int blockingCandidateCount) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptFieldStateCount", records.size());
        metadata.put("promptBlockingFieldStateCount", blockingCandidateCount);
        metadata.put("promptFieldStateLedger", records.stream()
                .map(PromptFieldStateRecord::toMetadataMap)
                .toList());
        metadata.put("promptFieldStateSummary", summary());
        return metadata;
    }

    private Map<String, Object> summary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("fieldStateCount", records.size());
        summary.put("sourceFieldCount", sourceFieldCount);
        summary.put("rawUserFieldCount", rawUserFieldCount);
        summary.put("finalUserFieldCount", finalUserFieldCount);
        summary.put("projectionDiffCount", projectionDiffCount);
        summary.put("blockingCandidateCount", blockingCandidateCount);
        summary.put("stateCounts", stateCounts());
        return summary;
    }

    private Map<String, Integer> stateCounts() {
        Map<PromptFieldState, Integer> counts = new EnumMap<>(PromptFieldState.class);
        for (PromptFieldStateRecord record : records) {
            counts.merge(record.fieldState(), 1, Integer::sum);
        }
        Map<String, Integer> result = new LinkedHashMap<>();
        for (PromptFieldState state : PromptFieldState.values()) {
            result.put(state.name(), counts.getOrDefault(state, 0));
        }
        return result;
    }
}
