package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PromptSourceContextSnapshot(
        List<PromptSourceContextFieldSnapshot> fields,
        int traversalDepthLimitCount,
        int traversalCycleCount,
        int traversalErrorCount,
        boolean exhaustive,
        int traversalFailureCount) {

    public PromptSourceContextSnapshot(
            List<PromptSourceContextFieldSnapshot> fields,
            int traversalDepthLimitCount,
            int traversalCycleCount,
            int traversalErrorCount) {
        this(fields,
                traversalDepthLimitCount,
                traversalCycleCount,
                traversalErrorCount,
                traversalDepthLimitCount == 0 && traversalCycleCount == 0 && traversalErrorCount == 0,
                traversalDepthLimitCount + traversalCycleCount + traversalErrorCount);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptSourceContextFieldCount", fields.size());
        metadata.put("promptSourceContextTraversalDepthLimitCount", traversalDepthLimitCount);
        metadata.put("promptSourceContextTraversalCycleCount", traversalCycleCount);
        metadata.put("promptSourceContextTraversalErrorCount", traversalErrorCount);
        metadata.put("promptSourceContextExhaustive", exhaustive);
        metadata.put("promptSourceContextFailureCount", traversalFailureCount);
        metadata.put("promptSourceContextLedger", fields.stream()
                .map(PromptSourceContextFieldSnapshot::toMetadataMap)
                .toList());
        metadata.put("promptSourceContextSummary", summary());
        return metadata;
    }

    private Map<String, Object> summary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("fieldCount", fields.size());
        summary.put("traversalDepthLimitCount", traversalDepthLimitCount);
        summary.put("traversalCycleCount", traversalCycleCount);
        summary.put("traversalErrorCount", traversalErrorCount);
        summary.put("exhaustive", exhaustive);
        summary.put("traversalFailureCount", traversalFailureCount);
        return summary;
    }
}
