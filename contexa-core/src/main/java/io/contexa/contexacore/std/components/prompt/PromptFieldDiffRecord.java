package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;

public record PromptFieldDiffRecord(
        String fieldKey,
        String sectionKey,
        String sectionTitle,
        String label,
        PromptFieldDiffType diffType,
        String rawValueHash,
        String finalValueHash,
        int rawLineNumber,
        int finalLineNumber,
        String reason,
        boolean blockingCandidate) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sectionKey", sectionKey);
        metadata.put("sectionTitle", sectionTitle);
        metadata.put("label", label);
        metadata.put("diffType", diffType.name());
        metadata.put("rawValueHash", rawValueHash);
        metadata.put("finalValueHash", finalValueHash);
        metadata.put("rawLineNumber", rawLineNumber);
        metadata.put("finalLineNumber", finalLineNumber);
        metadata.put("reason", reason);
        metadata.put("blockingCandidate", blockingCandidate);
        return metadata;
    }
}
