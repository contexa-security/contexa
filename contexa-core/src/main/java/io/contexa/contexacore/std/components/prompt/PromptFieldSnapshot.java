package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;

public record PromptFieldSnapshot(
        String fieldKey,
        String sectionKey,
        String sectionTitle,
        String label,
        String valueHash,
        int valueLength,
        int lineNumber,
        String valuePreview,
        boolean compactedMarker,
        boolean truncatedMarker) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sectionKey", sectionKey);
        metadata.put("sectionTitle", sectionTitle);
        metadata.put("label", label);
        metadata.put("valueHash", valueHash);
        metadata.put("valueLength", valueLength);
        metadata.put("lineNumber", lineNumber);
        metadata.put("valuePreview", valuePreview);
        metadata.put("compactedMarker", compactedMarker);
        metadata.put("truncatedMarker", truncatedMarker);
        return metadata;
    }
}
