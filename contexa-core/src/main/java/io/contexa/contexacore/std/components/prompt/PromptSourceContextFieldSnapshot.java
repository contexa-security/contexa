package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;

public record PromptSourceContextFieldSnapshot(
        String sourcePath,
        String sourceType,
        String valueType,
        String valueHash,
        int valueLength,
        String valueText) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("sourcePath", sourcePath);
        metadata.put("sourceType", sourceType);
        metadata.put("valueType", valueType);
        metadata.put("valueHash", valueHash);
        metadata.put("valueLength", valueLength);
        metadata.put("valueText", valueText);
        return metadata;
    }
}
